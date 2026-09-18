"""Reproducible A–F domain-transfer experiments, isolated from runtime releases.

Run with .venv_linux/bin/python -m experiments.domain_shift --stage audit
Raw CICIDS files and the deployed candidate are never overwritten.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
import torch
from scipy.stats import ks_2samp
from scipy.spatial.distance import jensenshannon
from sklearn.metrics import roc_auc_score
from xgboost import DMatrix

from agent2_detection_product.evaluation.cicids import FEATURE_COLUMNS, forward_matrix, metrics
from agent2_detection_product.evaluation.train import LABELS, BaseStack
from agent2_detection_product.contracts import feature

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / 'artifacts/pipeline/2.0.0-sim-20260918'
OUTPUT = ROOT / 'artifacts/experiments/domain-shift-20260918'
DATASET = ROOT / 'ingestion/dataset/CICIDS2017_improved'
PATHS = ['flow.packet_count', 'flow.duration_s', 'flow.pps', 'flow.iat_s_mean',
         'flow.iat_s_min', 'flow.iat_s_max', 'flow.psh_count', 'flow.urg_count', 'flow.rst_count']
META_NAMES = [*[f'base_{x}' for x in LABELS], *[f'present_{x}' for x in LABELS],
              'visibility', 'history_count', 'history_duration_ms', 'window_complete',
              'baseline_mature', 'drift', 'queue_age', 'score_entropy', 'score_margin',
              'score_disagreement', 'energy', 'ae_error', 'iforest', 'prototype_distance']


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False,
        default=lambda v: v.item() if isinstance(v, np.generic) else v.tolist()) + '\n')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def partitions():
    return {s: [json.loads(line) for line in (RELEASE / f'agent2_dataset/{s}.jsonl').read_text().splitlines()]
            for s in ('train', 'validation', 'test')}


def load_external():
    cache = OUTPUT / 'external.npz'
    if cache.exists():
        return dict(np.load(cache, allow_pickle=False))
    raw, protocols, labels, files, row_ids = [], [], [], [], []
    inventory = []
    for file_index, path in enumerate(sorted(DATASET.glob('*.csv'))):
        total = invalid = 0
        for frame in pd.read_csv(path, usecols=[*FEATURE_COLUMNS, 'Label'], chunksize=65536):
            x, valid, _, _ = forward_matrix(frame, PATHS)
            raw.append(x[valid].astype(np.float32))
            protocols.append(frame.loc[valid, 'Protocol'].to_numpy(np.int16))
            labels.append(frame.loc[valid, 'Label'].astype(str).str.strip().to_numpy())
            files.append(np.full(valid.sum(), file_index, dtype=np.int8))
            row_ids.append(frame.index.to_numpy()[valid] + 2)
            total += len(frame)
            invalid += int((~valid).sum())
        inventory.append({'file': path.name, 'sha256': digest(path), 'total': total, 'invalid': invalid})
        print(f'Cached {path.name}: {total:,} rows', flush=True)
    label_values, code = np.unique(np.concatenate(labels), return_inverse=True)
    result = {'raw': np.concatenate(raw), 'protocol': np.concatenate(protocols),
              'label': code.astype(np.int16), 'label_names': label_values.astype(str),
              'file_id': np.concatenate(files), 'csv_row': np.concatenate(row_ids),
              'file_names': np.asarray([p['file'] for p in inventory])}
    np.savez_compressed(cache, **result)
    write_json(OUTPUT / 'inputs.json', {'release_sha256': digest(RELEASE / 'agent2/manifest.json'),
        'external': inventory, 'seed': 26, 'feature_paths': PATHS,
        'test_status': 'Previously inspected external development benchmark, not a fresh blinded test.',
        'E_holdout': 'All Monday excluded from E evaluation; Monday benign features used for adaptation only.'})
    return result


def transform(base, raw):
    raw = np.asarray(raw, np.float32)
    mask = np.isfinite(raw).astype(np.float32)
    values = np.clip(np.where(mask.astype(bool), (raw-base.preprocessor.mean)/base.preprocessor.scale, 0), -20, 20).astype(np.float32)
    return values, mask


def stages(bundle, raw, *, visibility=None, count=None, duration=None, overrides=()):
    values, mask = transform(bundle.base, raw)
    embeddings = bundle.base.ssl.embed(values, mask)
    aux = bundle.base.auxiliary(embeddings)
    base_x = np.column_stack((values, mask, embeddings, aux))
    base = bundle.base.known.predict(base_x)
    paths = bundle.base.paths
    n = len(raw)
    zero = np.zeros(n)
    if visibility is None: visibility = mask.mean(axis=1)
    if count is None: count = raw[:, paths.index('flow.packet_count')] if 'flow.packet_count' in paths else zero
    if duration is None: duration = raw[:, paths.index('flow.duration_s')] * 1000 if 'flow.duration_s' in paths else zero
    if 'count' in overrides: count = zero
    if 'duration' in overrides: duration = zero
    if 'visibility' in overrides: visibility = np.ones(n)
    ordered = np.sort(base, axis=1)[:, ::-1]
    entropy = np.mean(-base*np.log(np.maximum(base, 1e-9))-(1-base)*np.log(np.maximum(1-base, 1e-9)), axis=1)
    meta_x = np.column_stack((base, np.ones_like(base), visibility, count, duration,
                             zero, zero, zero, zero, entropy, ordered[:, 0]-ordered[:, 1], base.std(axis=1), aux))
    meta = bundle.meta.predict(meta_x)
    calibrated = np.column_stack([bundle.calibrators[label].predict(meta[:, i]) for i, label in enumerate(LABELS)])
    return base, meta, calibrated, base_x, meta_x


def predict_all(bundle, data, *, overrides=(), save=None):
    indices = [PATHS.index(p) for p in bundle.base.paths]
    results = []
    for lo in range(0, len(data['raw']), 16384):
        original = data['raw'][lo:lo+16384]
        out = stages(bundle, original[:, indices], visibility=np.isfinite(original).mean(axis=1),
                     count=original[:, 0], duration=original[:, 1]*1000, overrides=overrides)
        results.append(np.stack(out[:3], axis=1))
    result = np.concatenate(results)
    if save: np.save(save, result)
    return result


def external_metrics(data, probabilities, thresholds, subset=None):
    selected = np.ones(len(data['raw']), bool) if subset is None else subset
    labels = data['label_names'][data['label'][selected]]
    # Scalar threshold comparisons against float32 can round a nextafter(float64)
    # threshold back onto a tied score, unlike the vector comparison in metrics().
    # Evaluate both paths in float64 so operating-point counts agree exactly.
    probability=np.asarray(probabilities[selected],dtype=np.float64)
    report=metrics(labels, probability, thresholds)
    benign=labels=='BENIGN'
    report['benign_fpr_by_head']={label:float((probability[benign,i]>=thresholds[label]).mean()) for i,label in enumerate(LABELS)}
    for i,label in enumerate(LABELS[:2]):
        positive=np.asarray(['ddos' in x.lower() if i==0 else 'portscan' in x.lower().replace(' ','') for x in labels])
        if positive.any():
            assert abs(report['per_label'][label]['recall']-float((probability[positive,i]>=thresholds[label]).mean()))<1e-12
    return report


def brief_metrics(report):
    return {'benign_fpr': report['binary_any_attack']['fpr'],
            'ddos_f1': report['per_label']['DDoS']['f1'],
            'ddos_auc': report['per_label']['DDoS']['roc_auc'],
            'scan_f1': report['per_label']['PORT_SCAN']['f1'],
            'scan_recall': report['per_label']['PORT_SCAN']['recall'],
            'scan_fpr_all_non_scan': report['per_label']['PORT_SCAN']['fpr']}


def group_masks(names, label):
    benign = names == 'BENIGN'
    positive = np.asarray(['ddos' in s.lower() if label == 'DDoS' else
                           'portscan' in s.lower().replace(' ', '') if label == 'PORT_SCAN' else
                           s == 'DATA_EXFILTRATION' for s in names])
    return {'benign': benign, 'positive': positive, 'other_attack': ~benign & ~positive}


def score_stats(values):
    if not len(values): return {'n': 0, 'status': 'no_matching_ground_truth'}
    return {'n': len(values), 'exact_one_fraction': float((values == 1).mean()),
            'exact_zero_fraction': float((values == 0).mean()), 'unique': len(np.unique(values)),
            'quantiles': np.quantile(values, [0, .01, .05, .25, .5, .75, .95, .99, 1]),
            'histogram_50_bins': np.histogram(values, np.linspace(0, 1, 51))[0]}


def experiment_a(bundle, data, predictions, parts):
    sim = parts['test']
    envs = [r['observation'] for r in sim]
    base, aux = bundle.base.outputs(envs)
    meta = bundle.meta.predict(bundle.base.predict(envs))
    cal = bundle.predict_probabilities(envs)
    sim_stages = np.stack((base, meta, cal), axis=1)
    sim_labels = np.asarray([r['labels'][0] if r['labels'] else 'BENIGN' for r in sim])
    report = {'stage_order': ['base', 'meta_raw', 'calibrated'], 'heads': {}}
    for i, label in enumerate(LABELS):
        mapping = bundle.calibrators[label].model
        entry = {'calibrator_x': mapping.X_thresholds_, 'calibrator_y': mapping.y_thresholds_,
                 'threshold': 1.0, 'comparison': '>=', 'datasets': {}}
        for name, pred, labels in [('simulation_test', sim_stages, sim_labels),
                                   ('CICIDS', predictions, data['label_names'][data['label']])]:
            groups = group_masks(labels, label)
            # Simulation uses canonical PORT_SCAN, not dataset spelling.
            if name == 'simulation_test':
                groups['positive'] = labels == label
                groups['other_attack'] = (labels != 'BENIGN') & (labels != label)
            entry['datasets'][name] = {stage: {g: score_stats(pred[select, j, i]) for g, select in groups.items()}
                                       for j, stage in enumerate(report['stage_order'])}
        report['heads'][label] = entry
    write_json(OUTPUT / 'A_scores.json', report)
    return report


def summary(x):
    finite = x[np.isfinite(x)]
    if not len(finite): return {'n': len(x), 'missing_fraction': 1.0}
    q = np.quantile(finite, [.01, .05, .25, .5, .75, .95, .99])
    return dict(n=len(x), finite=len(finite), missing_fraction=float(1-len(finite)/len(x)),
                p01=q[0], p05=q[1], q25=q[2], median=q[3], q75=q[4], iqr=q[4]-q[2], p95=q[5], p99=q[6])


def shift(a, b, categorical=False):
    af, bf = a[np.isfinite(a)], b[np.isfinite(b)]
    # Reference-derived deciles; explicit overflow and missing bins. Natural-log PSI, base-2 JSD.
    if categorical:
        categories = np.union1d(af, bf)
        p = np.asarray([(af == c).sum() for c in categories] + [len(a)-len(af)], float)
        q = np.asarray([(bf == c).sum() for c in categories] + [len(b)-len(bf)], float)
    else:
        cut = np.unique(np.quantile(af, np.linspace(0, 1, 11))) if len(af) else np.asarray([0.0])
        # Separate equality at the reference maximum from unseen larger values,
        # crucial when synthetic flag features are constant zero.
        edges = np.r_[-np.inf, cut, np.nextafter(cut[-1],np.inf), np.inf]
        p = np.r_[np.histogram(af, edges)[0], len(a)-len(af)].astype(float)
        q = np.r_[np.histogram(bf, edges)[0], len(b)-len(bf)].astype(float)
    p = (p+.5)/(p.sum()+.5*len(p))
    q = (q+.5)/(q.sum()+.5*len(q))
    return {'KS': float(ks_2samp(af, bf).statistic) if len(af) and len(bf) else None,
            'PSI': float(np.sum((q-p)*np.log(q/p))), 'JSD_bits': float(jensenshannon(p,q,base=2)**2),
            'missing_shift': float(np.isnan(b).mean()-np.isnan(a).mean())}


def experiment_b(bundle, data, parts):
    benign = [r['observation'] for r in parts['train'] if not r['labels']]
    a = bundle.base.preprocessor.raw(benign)
    proto = np.asarray([6 if e['protocol'] in ('TCP','TLS') else 17 if e['protocol'] in ('UDP','DNS','QUIC') else 0 for e in benign])
    a = np.column_stack((a, proto))
    b = np.column_stack((data['raw'], data['protocol']))[data['label_names'][data['label']] == 'BENIGN']
    rows = []
    for j, name in enumerate([*PATHS, 'protocol']):
        row = {'feature': name, **shift(a[:,j], b[:,j], name == 'protocol')}
        row.update({f'sim_{k}': v for k,v in summary(a[:,j]).items()})
        row.update({f'cicids_{k}': v for k,v in summary(b[:,j]).items()})
        rows.append(row)
    frame = pd.DataFrame(rows).sort_values('JSD_bits', ascending=False)
    frame.to_csv(OUTPUT / 'B_feature_drift.csv', index=False)
    write_json(OUTPUT / 'B_feature_drift.json', {'ranking': frame.fillna('not_available').to_dict('records'),
        'PSI_bins': 'simulation benign deciles plus underflow/overflow/missing; Jeffreys 0.5 count smoothing',
        'JSD': 'base 2 divergence, range [0,1], same bins; includes missingness',
        'KS': 'finite values only; protocol encoded TCP=6/UDP=17/other=0; categorical JSD/PSI preferred',
        'simulation_population': 'actual sampled training observations, packet-prefix weighted',
        'external_population': 'all valid BENIGN completed forward flow summaries',
        'protocol_in_model': 'not an explicit numeric feature; implicitly present through TCP flag availability'})
    return frame


def experiment_c(bundle, data, predictions, parts):
    rng = np.random.default_rng(26)
    benign = data['label_names'][data['label']] == 'BENIGN'
    select = np.flatnonzero(benign & (predictions[:,2,0] == 1))
    select = rng.choice(select, min(512, len(select)), replace=False)
    envs = [r['observation'] for r in parts['train'] if not r['labels']]
    sim_raw = bundle.base.preprocessor.raw(envs)
    tree_rows = []
    for population, raw in [('CICIDS_benign_DDoS_FP', data['raw'][select]), ('simulation_benign', sim_raw)]:
        outputs = stages(bundle, raw)
        for stage, models, x, names in [('base', bundle.base.known.models, outputs[3],
             [*PATHS, *['mask:'+p for p in PATHS], *[f'latent_{i}' for i in range(32)], *META_NAMES[-4:]]),
             ('meta', bundle.meta.models, outputs[4], META_NAMES)]:
            for label in LABELS:
                booster = models[label].get_booster()
                contrib = booster.predict(DMatrix(x), pred_contribs=True)
                margin = booster.predict(DMatrix(x), output_margin=True)
                assert np.allclose(contrib.sum(axis=1), margin, atol=2e-5)
                for j, name in enumerate(names):
                    tree_rows.append({'population':population, 'stage':stage, 'head':label, 'feature':name,
                        'mean_abs_SHAP_log_odds':float(np.abs(contrib[:,j]).mean()),
                        'mean_signed_SHAP_log_odds':float(contrib[:,j].mean()), 'n':len(raw)})
    pd.DataFrame(tree_rows).to_csv(OUTPUT/'C_tree_shap.csv', index=False)
    # End-to-end permutation Shapley, exact model evaluation; Monte Carlo attribution.
    # Includes derived count/duration context automatically; visibility is recalculated.
    # This is interventional attribution and may combine physically incompatible fields.
    results = []
    for population, raw in [('CICIDS_benign_DDoS_FP', data['raw'][select[:128]]), ('simulation_benign', sim_raw[:128])]:
        attribution = np.zeros((len(raw), len(PATHS)))
        baseline_predictions = []
        final = stages(bundle, raw)[1][:,0]
        for _ in range(32):
            current = sim_raw[rng.integers(len(sim_raw), size=len(raw))].copy()
            previous = stages(bundle, current)[1][:,0]
            baseline_predictions.append(previous)
            for j in rng.permutation(len(PATHS)):
                current[:,j] = raw[:,j]
                value = stages(bundle, current)[1][:,0]
                attribution[:,j] += (value-previous)/32
                previous = value
        assert np.allclose(attribution.sum(axis=1), final-np.mean(baseline_predictions,axis=0), atol=2e-6)
        for j,p in enumerate(PATHS):
            results.append({'population':population, 'feature':p, 'mean_abs_shap_probability':float(np.abs(attribution[:,j]).mean()),
                            'mean_signed_shap_probability':float(attribution[:,j].mean()), 'n':len(raw), 'permutations':32})
    pd.DataFrame(results).to_csv(OUTPUT/'C_end_to_end_shap.csv', index=False)
    write_json(OUTPUT/'C_method.json', {'tree':'XGBoost exact TreeSHAP, raw log-odds, additivity verified',
        'end_to_end':'32 random-order interventional Shapley paths on pre-isotonic DDoS probability, 128 records/population; additivity verified',
        'limits':'Latent SHAP is not original-feature SHAP. Raw interventional combinations may violate IAT relationships; use D retraining for corroboration.'})


def audit():
    data = load_external()
    bundle = joblib.load(RELEASE/'agent2/bundle.joblib')
    parts = partitions()
    cache = OUTPUT/'baseline_stages.npy'
    predictions = np.load(cache) if cache.exists() else predict_all(bundle, data, save=cache)
    print('Running A: full-population score audit', flush=True)
    experiment_a(bundle, data, predictions, parts)
    print('Running B: full-population benign feature drift', flush=True)
    frame = experiment_b(bundle, data, parts)
    print(frame[['feature','KS','PSI','JSD_bits']].to_string(index=False), flush=True)
    print('Running C: stage TreeSHAP and end-to-end Shapley', flush=True)
    experiment_c(bundle, data, predictions, parts)
    report = external_metrics(data, predictions[:,2], {label:1.0 for label in LABELS})
    write_json(OUTPUT/'baseline_metrics.json',report)
    print(json.dumps(brief_metrics(report)), flush=True)


def change_context(parts, overrides):
    result = deepcopy(parts)
    for rows in result.values():
        for row in rows:
            env = row['observation']
            if 'duration' in overrides: env['history']['duration_ms'] = 0
            if 'count' in overrides: env['history']['event_count'] = 0
            if 'visibility' in overrides: env['visibility']['feature_availability_ratio'] = 1.0
    return result


def fit_candidate(parts, paths, name, base_class=None):
    from unittest.mock import patch
    from agent2_detection_product.evaluation import train as trainer
    path = OUTPUT/name
    path.mkdir(parents=True, exist_ok=True)
    cached = path/'bundle.joblib'
    if cached.exists():
        return joblib.load(cached), json.loads((path/'policy.json').read_text())
    with patch.object(trainer, 'BaseStack', base_class or BaseStack):
        bundle, policy, report = trainer.train(parts['train'], parts['validation'], paths,
            version='2.0.0-'+name.replace('/','-').replace('_','-'), epochs=8, trees=60, folds=3)
    joblib.dump(bundle,cached)
    write_json(path/'policy.json',policy)
    write_json(path/'training_report.json', report)
    return bundle,policy


def ablation():
    data, parts = load_external(), partitions()
    variants = [(p.split('.')[-1], [p], ('count',) if p=='flow.packet_count' else
                 ('duration',) if p=='flow.duration_s' else ()) for p in PATHS]
    variants += [('all_timing', PATHS[1:6], ('duration',)),
                 ('protocol_proxies', PATHS[6:9], ('visibility',)),
                 ('visibility_context_only', [], ('visibility',))]
    summary_rows=[]
    for name, removed, overrides in variants:
        output=OUTPUT/f'D/{name}/external_metrics.json'
        if output.exists():
            report=json.loads(output.read_text())
        else:
            print(f'D: retrain minus {name}; overrides={overrides}',flush=True)
            changed=change_context(parts,overrides)
            bundle,policy=fit_candidate(changed,[p for p in PATHS if p not in removed],f'D/{name}')
            scores=predict_all(bundle,data,overrides=overrides)
            report=external_metrics(data,scores[:,2],policy['thresholds'])
            report['raw_ddos_auc']=float(roc_auc_score(
                ['ddos' in s.lower() for s in data['label_names'][data['label']]],scores[:,1,0]))
            report['removed_paths']=removed
            report['removed_context_aliases']=list(overrides)
            report['thresholds']={k:policy['thresholds'][k] for k in LABELS}
            write_json(output,report)
        summary_rows.append({'removed':name,**brief_metrics(report),'raw_ddos_auc':report['raw_ddos_auc']})
        pd.DataFrame(summary_rows).to_csv(OUTPUT/'D_ablation.csv',index=False)
        print(name, brief_metrics(report),flush=True)
    write_json(OUTPUT/'D_method.json',{'training':'whole unchanged V2 stack retrained, 8 epochs, 60 trees, 3 group OOF folds, same simulation partitions',
        'thresholds':'reselected only on unchanged simulation validation, 1% FPR/85% recall gates; failed gates remain reported',
        'external':'all 2,099,943 valid rows each variant',
        'protocol':'no numeric protocol in V2; remove all three flag values/masks and fix visibility context to 1',
        'alias_control':'duration and packet_count also removed from meta history context; timing group removes duration/pps/all IAT',
        'interpretation':'retraining/OOF/feature interaction experiment; not inference-time zeroing'})


class BenignAdaptedStack(BaseStack):
    """Same model architecture, representation/normality fitting adds benign Monday.

    Downstream heads are refitted on synthetic labels so changed latent coordinates
    are never fed into stale supervised weights. External attack labels absent.
    """
    external_envelopes = ()

    def fit(self, envelopes, targets, *, split):
        from agent2_detection_product.models.shared_ssl_encoder import MaskedPreprocessor,SSLEncoder
        from agent2_detection_product.models.anomaly_autoencoder import BenignAutoencoder
        from agent2_detection_product.models.anomaly_iforest import LatentIsolationForest
        from agent2_detection_product.models.open_set_energy import EnergyHead,PrototypeDistance
        from agent2_detection_product.models.tabular_known_xgb import KnownXGBoost
        if split!='train': raise ValueError('training only')
        torch.manual_seed(26)
        all_envs=list(envelopes)+list(self.external_envelopes)
        self.preprocessor=MaskedPreprocessor(self.paths).fit(all_envs,split=split)
        values,masks=self.preprocessor.transform(all_envs)
        self.ssl=SSLEncoder(len(self.paths)).fit(values,masks,split=split,epochs=self.epochs)
        embeddings=self.ssl.embed(values,masks)
        synthetic=embeddings[:len(envelopes)]
        benign=np.asarray(targets).sum(axis=1)==0
        normal=np.concatenate((synthetic[benign],embeddings[len(envelopes):]))
        self.ae=BenignAutoencoder(32).fit(normal,split=split,verified_benign=True,epochs=self.epochs)
        self.iforest=LatentIsolationForest().fit(normal,split=split)
        energy_y=np.where(benign,0,np.argmax(targets,axis=1)+1)
        self.energy=EnergyHead(32,len(LABELS)+1).fit(synthetic,energy_y,split=split,epochs=self.epochs)
        self.prototypes=PrototypeDistance().fit(synthetic,energy_y,split=split)
        x=np.column_stack((values[:len(envelopes)],masks[:len(envelopes)],synthetic,self.auxiliary(synthetic)))
        self.known=KnownXGBoost(LABELS,n_estimators=self.trees).fit(x,targets,split=split)
        return self


def external_envelopes(data, indices):
    template=partitions()['train'][0]['observation']
    envs=[]
    for idx in indices:
        raw=data['raw'][idx]
        env=deepcopy(template)
        env['sensor_id']='monday-adaptation'
        env['event_id']=f"monday-{int(data['csv_row'][idx])}"
        env['protocol']='TCP' if data['protocol'][idx]==6 else 'UDP'
        env['features']={k:{} for k in ('flow','window','dns','tls')}
        for path,value in zip(PATHS,raw):
            env['features']['flow'][path.split('.')[1]]={'value':float(value) if np.isfinite(value) else None,
                'available':bool(np.isfinite(value)), 'applicable':True, 'reason':'OBSERVED' if np.isfinite(value) else 'NOT_OBSERVED'}
        env['history']={'event_count':int(raw[0]),'duration_ms':float(raw[1])*1000,'window_complete':False}
        env['visibility']['feature_availability_ratio']=float(np.isfinite(raw).mean())
        envs.append(env)
    return envs


def adaptation():
    data,parts=load_external(),partitions()
    monday=np.flatnonzero(data['file_id']==list(data['file_names']).index('monday.csv'))
    # Monday is the designated benign-only capture. No attack labels are passed
    # to representation, normality, baseline, or threshold fitting.
    assert np.all(data['label_names'][data['label'][monday]]=='BENIGN')
    rng=np.random.default_rng(26)
    rng.shuffle(monday)
    adapt_ids,cal_ids,diag_ids=monday[:4096],monday[4096:8192],monday[8192:12288]
    holdout=data['file_id']!=list(data['file_names']).index('monday.csv')
    write_json(OUTPUT/'E_partitions.json',{'adapt_rows':data['csv_row'][adapt_ids],
        'calibration_diagnostic_rows':data['csv_row'][cal_ids],'benign_diagnostic_rows':data['csv_row'][diag_ids],
        'source':'monday.csv benign-only capture','attack_labels_used_for_fitting':False,
        'evaluation':'Tuesday–Friday, all Monday excluded, identical subset for baseline',
        'baseline_fit':'preprocessor mean/scale, AE normality and isolation forest; all neural dimensions fixed',
        'calibration':'known-score simulation isotonic remains. Separate raw-score quantile operating-point diagnostic uses Monday only; not probability calibration.'})
    BenignAdaptedStack.external_envelopes=external_envelopes(data,adapt_ids)
    print('E: adapting SSL/AE/normality with 4,096 Monday benign flows; simulation labels only for known heads',flush=True)
    bundle,policy=fit_candidate(parts,PATHS,'E/adapted',BenignAdaptedStack)
    cache=OUTPUT/'E_adapted_stages.npy'
    scores=np.load(cache) if cache.exists() else predict_all(bundle,data,save=cache)
    baseline=np.load(OUTPUT/'baseline_stages.npy')
    results={}
    for name,pred,threshold in [('V2_same_Tue_Fri',baseline[:,2],{l:1.0 for l in LABELS}),
        ('SSL_AE_benign_adaptation',scores[:,2],policy['thresholds'])]:
        report=external_metrics(data,pred,threshold,holdout)
        results[name]=brief_metrics(report)
        write_json(OUTPUT/f'E/{name}.json',report)
    # The known benign negative class alone cannot fit isotonic probabilities.
    # A threshold strictly above a quantile plateau instead bounds the observed
    # calibration negative rate. Positive recall is an external measurement.
    for name,pred in [('frozen_V2',baseline[:,1]),('adapted',scores[:,1])]:
        threshold={label:float(np.nextafter(float(np.quantile(pred[cal_ids,i],.99)),np.inf)) for i,label in enumerate(LABELS)}
        report=external_metrics(data,pred,threshold,holdout)
        report['benign_only_thresholds']=threshold
        report['Monday_diagnostic_any_fpr']=float((pred[diag_ids]>=np.asarray(list(threshold.values()))).any(axis=1).mean())
        key=name+'_benign_raw_quantile'
        results[key]=brief_metrics(report)
        write_json(OUTPUT/f'E/{key}.json',report)
    write_json(OUTPUT/'E_summary.json',results)
    print(json.dumps(results,indent=2),flush=True)


def v2_final_partitions():
    """One end-of-capture/expiry snapshot per flow from immutable packet releases."""
    parts={s:[] for s in ('train','validation','test')}
    for folder in sorted((RELEASE/'simulation/scenarios').iterdir()):
        if not folder.is_dir(): continue
        manifest=json.loads((folder/'manifest.json').read_text())
        truth=json.loads((folder/'ground_truth.json').read_text())
        last={}
        for line in (folder/'observations.jsonl').open():
            env=json.loads(line)
            last[env['entity_keys']['flow_id']]=env
        split=manifest['split_assignment']
        run=manifest['generator_family'].split('_run')[-1]
        for env in last.values():
            labels=truth[env['event_id']]
            if set(labels)-set(LABELS): continue
            parts[split].append({'observation':env,'labels':labels,'verified':True,
                'group_id':f'{split}-run{run}','scenario_id':manifest['scenario_id'],
                'split':split,'generator_family':manifest['generator_family']})
    return parts


def v3():
    from agent1_observation_dns.simulation.v3_generator import generate
    directory=OUTPUT/'F/simulation_v3'
    if (directory/'manifest.json').exists():
        manifest=json.loads((directory/'manifest.json').read_text())
        rows=[json.loads(line) for split in ('train','validation','test') for line in (directory/f'{split}.jsonl').read_text().splitlines()]
    else:
        print('F: generating V3 packets with diverse benign and paired attack/hard-negative configurations',flush=True)
        rows,manifest=generate(directory,seed=26)
    data=load_external()
    baseline=np.load(OUTPUT/'baseline_stages.npy')
    results={}
    for name,parts in [('additive',partitions()),('final_flows_aligned_visibility',v2_final_partitions())]:
        for split in parts:
            parts[split].extend(r for r in rows if r['split']==split)
        if name=='final_flows_aligned_visibility':
            # Same visibility definition as CSV for the common-feature test,
            # never invent missing window/DNS/TLS measurements.
            for subset in parts.values():
                for row in subset:
                    env=row['observation']
                    available=[feature(env,p)[1] for p in PATHS]
                    env['visibility']['feature_availability_ratio']=sum(available)/len(PATHS)
        print(f'F {name}: training {len(parts["train"])} simulator observations',flush=True)
        bundle,policy=fit_candidate(parts,PATHS,f'F/{name}')
        scores=predict_all(bundle,data,save=OUTPUT/f'F/{name}/external_stages.npy')
        report=external_metrics(data,scores[:,2],policy['thresholds'])
        report['training_counts']={s:len(r) for s,r in parts.items()}
        write_json(OUTPUT/f'F/{name}/external_metrics.json',report)
        results[name]=brief_metrics(report)
        from agent2_detection_product.evaluation.metrics import binary_metrics
        test=parts['test']
        test_p=bundle.predict_probabilities([r['observation'] for r in test])
        write_json(OUTPUT/f'F/{name}/synthetic_test.json',{label:binary_metrics(
            [int(label in r['labels']) for r in test],test_p[:,i],policy['thresholds'][label]) for i,label in enumerate(LABELS)})
        preserved=scores[:,2].copy()
        preserved[:,1]=baseline[:,2,1]
        thresholds={**policy['thresholds'],'PORT_SCAN':1.0}
        report=external_metrics(data,preserved,thresholds)
        report['frozen_scan_control']='Original V2 scan bundle outputs substituted; original shared representation retained for that head. No deployed changes.'
        write_json(OUTPUT/f'F/{name}/frozen_scan_metrics.json',report)
        results[name+'_frozen_scan']=brief_metrics(report)
        print(name,results[name],flush=True)
    write_json(OUTPUT/'F_summary.json',{'metrics':results,'simulation':{k:manifest[k] for k in (
        'packet_count','rows','executed_configurations','cartesian_plan_size','full_cartesian_executed')},
        'attack_labels_used_for_training':'synthetic only',
        'limits':'V3 broad support was motivated by A–C external diagnostics. CICIDS is now a development benchmark; a new dataset is required for an unbiased transfer claim. Existing architecture unchanged; window coordination cannot be evaluated from the nine-column adapter.'})


def supplemental():
    bundle=joblib.load(RELEASE/'agent2/bundle.joblib')
    data=load_external()
    predictions=np.load(OUTPUT/'baseline_stages.npy')
    dump=bundle.base.known.models['DDoS'].get_booster().get_dump(dump_format='json')
    split_rows=[]
    def visit(node):
        if 'split' in node:
            idx=int(node['split'][1:])
            value=node['split_condition']
            split_rows.append({'feature_index':idx,'feature':PATHS[idx] if idx<len(PATHS) else f'input_{idx}',
                 'raw_threshold':float(value*bundle.base.preprocessor.scale[idx]+bundle.base.preprocessor.mean[idx]) if idx<len(PATHS) else value})
            for child in node['children']: visit(child)
    for tree in dump: visit(json.loads(tree))
    unique={json.dumps(x,sort_keys=True):x for x in split_rows}
    labels=data['label_names'][data['label']]
    pps=data['raw'][:,2]
    cohorts={}
    for name,mask in [('benign',labels=='BENIGN'),('DDoS',np.asarray(['ddos' in x.lower() for x in labels]))]:
        cohorts[name]={'n':int(mask.sum()),'raw_meta_auc_note':'see stage_metrics',
            'pps':summary(pps[mask]),'pps_missing_fraction':float(np.isnan(pps[mask]).mean())}
    write_json(OUTPUT/'C_exact_tree_rules.json',{'base_ddos_splits':list(unique.values()),
        'cohorts':cohorts,'note':'Raw thresholds reverse the frozen z-score transform. Conditions outside +/-20 clipping support share leaves.'})
    stage_metrics={}
    for j,name in enumerate(('base','meta_raw','calibrated')):
        stage_metrics[name]=brief_metrics(external_metrics(data,predictions[:,j],{l:1.0 for l in LABELS}))
    write_json(OUTPUT/'A_stage_metrics.json',stage_metrics)
    # Agent 1 checkpoints have no usable input in CICIDS flow CSVs. Audit held-out
    # simulated DNS scores and explicit runtime absence instead of fabricating data.
    from agent1_observation_dns.models.dga_context_xgb.model import ContextBranch
    from agent1_observation_dns.models.dga_char_attention.model import CharacterBranch
    from agent1_observation_dns.models.dns_tunnel_fast_gbdt.model import FastBranch
    from agent1_observation_dns.models.dns_tunnel_bytecnn.model import ByteBranch
    from agent1_observation_dns.models.dns_tunnel_sequence.model import SequenceBranch
    branches={'dga_context_xgb':ContextBranch,'dga_char_attention':CharacterBranch,
              'dns_tunnel_fast_gbdt':FastBranch,'dns_tunnel_bytecnn':ByteBranch,'dns_tunnel_sequence':SequenceBranch}
    result={}
    malicious_domains=set()
    for target in ('dga','dns_tunnel'):
        for line in (RELEASE/f'agent1/{target}_rows.jsonl').read_text().splitlines():
            row=json.loads(line)
            if row['label']: malicious_domains.add((row['scenario_id'],row['domain']))
    for architecture,cls in branches.items():
        target='dga' if architecture.startswith('dga') else 'dns_tunnel'
        corpus=[json.loads(line) for line in (RELEASE/f'agent1/{target}_rows.jsonl').read_text().splitlines()]
        corpus=[r for r in corpus if r['split_assignment']=='test']
        path=RELEASE/'agent1'/(architecture+('.json' if architecture.endswith(('xgb','gbdt')) else '.pt'))
        branch=cls(path)
        groups={g:[] for g in ('benign','positive','other_attack')}
        absent={g:0 for g in groups}
        for i,row in enumerate(corpus):
            group='positive' if row['label'] else 'other_attack' if (row['scenario_id'],row['domain']) in malicious_domains else 'benign'
            score=branch.predict(str(i),row['domain'],row['context'])
            if score.score_present: groups[group].append(score.probability)
            else: absent[group]+=1
        result[architecture]={'sim_test':{g:{**score_stats(np.asarray(values)), 'runtime_abstentions':absent[g]} for g,values in groups.items()},
                              'CICIDS':'not_evaluable: query names and DNS sequences absent'}
    write_json(OUTPUT/'A_agent1_scores.json',result)


def plots():
    import os
    os.environ.setdefault('MPLCONFIGDIR',str(OUTPUT/'matplotlib-cache'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,'figure.dpi':140})
    directory=OUTPUT/'figures'
    directory.mkdir(exist_ok=True)
    def save(fig,name):
        fig.savefig(directory/f'{name}.png',bbox_inches='tight')
        fig.savefig(directory/f'{name}.svg',bbox_inches='tight')
        plt.close(fig)
    audit=json.loads((OUTPUT/'A_scores.json').read_text())
    colors={'benign':'#2171b5','positive':'#cb181d','other_attack':'#e69500'}
    fig,axes=plt.subplots(3,2,figsize=(12,10),sharex=True)
    for i,label in enumerate(LABELS):
        for j,dataset in enumerate(('simulation_test','CICIDS')):
            ax=axes[i,j]
            for group,stats in audit['heads'][label]['datasets'][dataset]['calibrated'].items():
                if stats['n']:
                    ax.stairs(np.asarray(stats['histogram_50_bins'])/stats['n'],np.linspace(0,1,51),label=f'{group} (n={stats["n"]:,})',color=colors[group],linewidth=1.5)
            ax.set_title(f'{label} · {dataset.replace("_"," ")}')
            ax.set_yscale('symlog',linthresh=.001)
            ax.set_ylabel('Fraction within cohort')
            ax.legend(fontsize=8,loc='upper center')
    for ax in axes[-1]: ax.set_xlabel('Calibrated candidate score (50 equal-width bins)')
    fig.suptitle('A · Score saturation and out-of-domain false positives',fontsize=15)
    fig.tight_layout(rect=(0,0,1,.97))
    save(fig,'A_score_histograms')
    fig,axes=plt.subplots(1,3,figsize=(14,4))
    for i,label in enumerate(LABELS):
        for stage,style in [('meta_raw','-'),('calibrated','--')]:
            for group in ('benign','positive'):
                stats=audit['heads'][label]['datasets']['CICIDS'][stage][group]
                if stats['n']:
                    axes[i].stairs(np.asarray(stats['histogram_50_bins'])/stats['n'],np.linspace(0,1,51),
                        label=f'{group}, {stage}',color=colors[group],linestyle=style)
        axes[i].set_title(label)
        axes[i].set_yscale('symlog',linthresh=.001)
        axes[i].legend(fontsize=7)
        axes[i].set_xlabel('Candidate score')
    axes[0].set_ylabel('Fraction within cohort')
    fig.tight_layout()
    save(fig,'A_before_after_isotonic')
    a1=json.loads((OUTPUT/'A_agent1_scores.json').read_text())
    fig,axes=plt.subplots(2,3,figsize=(13,7))
    for ax,(name,entry) in zip(axes.flat,a1.items()):
        for group,stats in entry['sim_test'].items():
            if stats['n']: ax.stairs(np.asarray(stats['histogram_50_bins'])/stats['n'],np.linspace(0,1,51),label=f'{group} n={stats["n"]}',color=colors[group])
        ax.set_title(name,fontsize=10)
        ax.set_xlabel('Uncalibrated specialist score')
        ax.legend(fontsize=7)
    axes.flat[-1].axis('off')
    axes.flat[-1].text(0,.7,'Agent 1: held-out simulation only\nCICIDS lacks DNS query inputs.\nAbstentions are counted in A_agent1_scores.json.',va='top')
    fig.tight_layout()
    save(fig,'A_agent1_histograms')
    drift=pd.read_csv(OUTPUT/'B_feature_drift.csv')
    fig,ax=plt.subplots(figsize=(9,5))
    ax.barh(drift['feature'][::-1],drift['JSD_bits'][::-1],color='#2171b5')
    ax.set_xlabel('Jensen–Shannon divergence (bits, 0–1)')
    ax.set_title('B · Benign feature shift (missingness included)')
    fig.tight_layout(); save(fig,'B_feature_shift')
    fig,ax=plt.subplots(figsize=(9,5))
    shap=pd.read_csv(OUTPUT/'C_end_to_end_shap.csv')
    shap=shap[shap.population=='CICIDS_benign_DDoS_FP'].sort_values('mean_abs_shap_probability')
    ax.barh(shap.feature,shap.mean_abs_shap_probability,color='#cb181d')
    ax.set_xlabel('Mean absolute Shapley contribution to raw DDoS probability')
    ax.set_title('C · End-to-end attribution on benign DDoS false positives\n128 flows; 32 random permutations; synthetic benign background')
    fig.tight_layout(); save(fig,'C_ddos_attribution')
    if (OUTPUT/'D_ablation.csv').exists():
        d=pd.read_csv(OUTPUT/'D_ablation.csv').sort_values('benign_fpr')
        fig,axes=plt.subplots(1,2,figsize=(12,6))
        axes[0].barh(d.removed,d.benign_fpr*100,color='#2171b5')
        axes[0].axvline(70.199,color='#cb181d',linestyle='--',label='V2 baseline')
        axes[0].set_xlabel('Benign any-head FPR (%)'); axes[0].legend()
        axes[1].barh(d.removed,d.ddos_auc,color='#31a354')
        axes[1].axvline(.5,color='gray',linestyle='--')
        axes[1].set_xlabel('DDoS ROC-AUC (calibrated)')
        fig.suptitle('D · Remove feature, retrain unchanged architecture')
        fig.tight_layout(); save(fig,'D_ablation')
    if (OUTPUT/'F_summary.json').exists():
        baseline=brief_metrics(json.loads((OUTPUT/'baseline_metrics.json').read_text()))
        variants=json.loads((OUTPUT/'F_summary.json').read_text())['metrics']
        names=['V2','V3 additive','V3 final flows','V3 + frozen scan']
        entries=[baseline,variants['additive'],variants['final_flows_aligned_visibility'],variants['final_flows_aligned_visibility_frozen_scan']]
        fig,axes=plt.subplots(1,4,figsize=(15,4.5))
        for ax,key,title in zip(axes,('benign_fpr','ddos_f1','scan_f1','ddos_auc'),('Benign FPR ↓','DDoS F1 ↑','Scan F1 ↑','DDoS ROC-AUC ↑')):
            vals=[e[key] for e in entries]
            bars=ax.bar(np.arange(4),vals,color=['#636363','#6baed6','#2171b5','#31a354'])
            for bar,v in zip(bars,vals): ax.text(bar.get_x()+bar.get_width()/2,v+.015,f'{v:.3f}',ha='center',fontsize=9)
            ax.set_xticks(np.arange(4),names,rotation=35,ha='right')
            ax.set_ylim(0,1.12); ax.set_title(title)
        fig.suptitle('F · Same external CICIDS benchmark; simulation-only known-head training')
        fig.tight_layout(); save(fig,'F_v2_v3_comparison')
    print(f'Wrote figures in {directory}',flush=True)


def threshold_sweep():
    data=load_external()
    variants=[('V2',RELEASE/'agent2/bundle.joblib',()),
              ('D_all_timing',OUTPUT/'D/all_timing/bundle.joblib',('duration',))]
    rows=[]
    labels=data['label_names'][data['label']]
    ddos=np.asarray(['ddos' in x.lower() for x in labels])
    benign=labels=='BENIGN'
    scan=np.asarray(['portscan' in x.lower().replace(' ','') for x in labels])
    for name,path,overrides in variants:
        bundle=joblib.load(path)
        cache=OUTPUT/f'{name}_threshold_stages.npy'
        scores=np.load(cache) if cache.exists() else predict_all(bundle,data,overrides=overrides,save=cache)
        raw=scores[:,1,0]
        for threshold in np.unique(np.r_[np.linspace(0,1,101),np.quantile(raw,np.linspace(.90,1,101))]):
            pred=raw>=threshold
            tp=int((pred&ddos).sum()); fp=int((pred&~ddos).sum()); fn=int((~pred&ddos).sum())
            rows.append({'variant':name,'threshold':float(threshold),'ddos_f1':2*tp/max(2*tp+fp+fn,1),
                'ddos_precision':tp/max(tp+fp,1),'ddos_recall':tp/max(tp+fn,1),
                'ddos_fpr_non_ddos':float(fp/max((~ddos).sum(),1)),
                'benign_fpr':float((pred&benign).sum()/max(benign.sum(),1)),
                'scan_fpr_non_scan':float((scores[:,1,1]>=1.0)[~scan].mean()),
                'score_99_9':float(np.quantile(raw,.999))})
    frame=pd.DataFrame(rows)
    frame.to_csv(OUTPUT/'G_threshold_sweep.csv',index=False)
    selected=frame[(frame.ddos_fpr_non_ddos<=.01)&(frame.ddos_recall>=.85)]
    best=frame.loc[frame.groupby('variant').ddos_f1.idxmax()].to_dict('records')
    write_json(OUTPUT/'G_threshold_summary.json',{'best_f1_by_variant':best,
        'thresholds_meeting_1pct_fpr_85pct_recall':selected.to_dict('records'),
        'note':'thresholds are diagnostic selections on the external benchmark and must not be used to claim an approved release'})
    print(json.dumps({'best':best,'eligible_count':len(selected)},indent=2),flush=True)


def _cohort_feature_rows(bundle, rows):
    envs=[r['observation'] for r in rows]
    raw=bundle.base.preprocessor.raw(envs)
    labels=np.asarray(['DDoS' if 'DDoS' in r['labels'] else 'BENIGN' if not r['labels'] else 'OTHER' for r in rows])
    scores=bundle.predict_probabilities(envs)[:,0]
    return raw,labels,scores


def _feature_summary(values):
    finite=values[np.isfinite(values)]
    if not len(finite): return {'n':len(values),'missing_fraction':1.0}
    q=np.quantile(finite,[.01,.05,.10,.50,.90,.95,.99])
    return {'n':len(values),'finite':len(finite),'missing_fraction':float(np.isnan(values).mean()),
            'p01':float(q[0]),'p05':float(q[1]),'p10':float(q[2]),'p50':float(q[3]),
            'p90':float(q[4]),'p95':float(q[5]),'p99':float(q[6])}


def ddos_diagnosis():
    from scipy.stats import ks_2samp
    data=load_external()
    # The CICIDS cache contains ~2.1M rows.  Keep every DDoS row and use a
    # deterministic, stratified sample of benign/other traffic for the
    # expensive embedding/SHAP pass.  The earlier B experiment already gives
    # exact full-dataset drift; this stage is focused on DDoS orientation and
    # attribution and must stay bounded in memory.
    all_names=data['label_names'][data['label']]
    rng=np.random.default_rng(26)
    keep=[]
    for name,limit in [('BENIGN',150_000)]:
        idx=np.flatnonzero(all_names==name)
        keep.append(idx if len(idx)<=limit else rng.choice(idx,limit,replace=False))
    ddos_idx=np.flatnonzero(np.asarray(['ddos' in x.lower() for x in all_names]))
    keep.append(ddos_idx)
    other_idx=np.flatnonzero((all_names!='BENIGN') & ~np.asarray(['ddos' in x.lower() for x in all_names]))
    keep.append(other_idx if len(other_idx)<=50_000 else rng.choice(other_idx,50_000,replace=False))
    keep=np.sort(np.concatenate(keep))
    data={k:(v[keep] if getattr(v,'ndim',0)>0 and len(v)==len(all_names) else v) for k,v in data.items()}
    print(f"DDoS diagnosis sample: {len(keep):,} rows (all {len(ddos_idx):,} DDoS)", flush=True)
    ext_labels=data['label_names'][data['label']]
    ext_benign=ext_labels=='BENIGN'
    ext_ddos=np.asarray(['ddos' in x.lower() for x in ext_labels])
    external_raw=data['raw']
    variants=[('V2',RELEASE/'agent2/bundle.joblib',()),
              ('V3_additive',OUTPUT/'F/additive/bundle.joblib',()),
              ('V3_final_flow',OUTPUT/'F/final_flows_aligned_visibility/bundle.joblib',())]
    orientation=[]; distributions=[]; feature_rows=[]; shap_rows=[]
    for variant,path,overrides in variants:
        print(f"Loading/scoring {variant}...", flush=True)
        bundle=joblib.load(path)
        external_scores=predict_all(bundle,data,overrides=overrides)[:,2,0]
        if variant=='V2':
            sim_rows=partitions()['test']
        elif variant=='V3_additive':
            sim_rows=[json.loads(line) for line in (OUTPUT/'F/simulation_v3/test.jsonl').read_text().splitlines()]
        else:
            sim_rows=[json.loads(line) for line in (OUTPUT/'F/simulation_v3/test.jsonl').read_text().splitlines()]
        sim_raw,sim_labels,sim_scores=_cohort_feature_rows(bundle,sim_rows)
        threshold=1.0
        if variant!='V2':
            # The V3 experiment's own policy is diagnostic only, but use it to
            # define TP/TN/FN cohorts consistently with that candidate run.
            policy=json.loads((path.parent/'policy.json').read_text())
            threshold=policy['thresholds']['DDoS']
        for name,scores,labels in [('simulation',sim_scores,sim_labels),('CICIDS',external_scores,ext_labels)]:
            groups={'benign':labels=='BENIGN','ddos':labels=='DDoS'}
            for group,mask in groups.items():
                values=scores[mask]
                distributions.append({'variant':variant,'population':name,'group':group,'threshold':threshold,
                    'orientation': 'higher=positive', **_feature_summary(values)})
            positive=labels=='DDoS'
            auc=float(roc_auc_score(positive,scores)) if positive.any() and (~positive).any() else None
            orientation.append({'variant':variant,'threshold':threshold,'auc_score':auc,
                'auc_inverted':float(roc_auc_score(positive,1-scores)) if auc is not None else None,
                'median_benign':float(np.median(scores[labels=='BENIGN'])) if (labels=='BENIGN').any() else None,
                'median_ddos':float(np.median(scores[positive])) if positive.any() else None,
                'class_order':{label:list(bundle.base.known.models[label].classes_) for label in LABELS},
                'calibrator_for_ddos_x':bundle.calibrators['DDoS'].model.X_thresholds_.tolist(),
                'calibrator_for_ddos_y':bundle.calibrators['DDoS'].model.y_thresholds_.tolist()})
        # Feature table aligns finite-value support and missingness. V2 raw
        # vectors use the model's exact paths; external uses the same order.
        ext_common=external_raw[:,[PATHS.index(p) for p in bundle.base.paths]]
        sim_masks={'benign':sim_labels=='BENIGN','ddos':sim_labels=='DDoS'}
        ext_masks={'benign':ext_benign,'ddos':ext_ddos}
        for j,feature_name in enumerate(bundle.base.paths):
            for group in ('benign','ddos'):
                row={'variant':variant,'feature':feature_name,'group':group}
                row.update({f'sim_{k}':v for k,v in _feature_summary(sim_raw[sim_masks[group],j]).items()})
                row.update({f'cicids_{k}':v for k,v in _feature_summary(ext_common[ext_masks[group],j]).items()})
                sf=sim_raw[sim_masks[group],j]; ef=ext_common[ext_masks[group],j]
                sfinite=sf[np.isfinite(sf)]; efinite=ef[np.isfinite(ef)]
                row['KS_sim_vs_cicids']=float(ks_2samp(sfinite,efinite).statistic) if len(sfinite) and len(efinite) else None
                feature_rows.append(row)
        # Exact base-tree SHAP for four requested cohorts.
        predictions=bundle.base.outputs([r['observation'] for r in sim_rows])
        sim_x=np.column_stack((bundle.base.preprocessor.transform([r['observation'] for r in sim_rows])[0],
            bundle.base.preprocessor.transform([r['observation'] for r in sim_rows])[1],
            bundle.base.ssl.embed(*bundle.base.preprocessor.transform([r['observation'] for r in sim_rows])),predictions[1]))
        ext_values,ext_masks_vec=transform(bundle.base,ext_common)
        ext_x=np.column_stack((ext_values,ext_masks_vec,bundle.base.ssl.embed(ext_values,ext_masks_vec),
            bundle.base.auxiliary(bundle.base.ssl.embed(ext_values,ext_masks_vec))))
        model=bundle.base.known.models['DDoS']; booster=model.get_booster()
        for population,labels,scores,x in [('sim_benign_TN',sim_labels,sim_scores,sim_x),
                                           ('sim_DDoS_TP',sim_labels,sim_scores,sim_x),
                                           ('CICIDS_benign_TN',ext_labels,external_scores,ext_x),
                                           ('CICIDS_DDoS_FN',ext_labels,external_scores,ext_x)]:
            if population.endswith('TN'): select=labels=='BENIGN';
            elif population=='sim_DDoS_TP': select=(labels=='DDoS')&(scores>=threshold)
            else: select=(labels=='DDoS')&(scores<threshold)
            if not select.any(): continue
            contributions=booster.predict(DMatrix(x[select]),pred_contribs=True)
            for j,feature_name in enumerate([*bundle.base.paths,*['mask:'+p for p in bundle.base.paths],*[f'latent_{i}' for i in range(32)],'energy','ae_error','iforest','prototype_distance']):
                vals=contributions[:,j]
                shap_rows.append({'variant':variant,'population':population,'feature':feature_name,'n':len(vals),
                    'mean_abs_SHAP_log_odds':float(np.abs(vals).mean()),'mean_signed_SHAP_log_odds':float(vals.mean())})
    write_json(OUTPUT/'H_ddos_orientation.json',orientation)
    pd.DataFrame(distributions).to_csv(OUTPUT/'H_ddos_score_distributions.csv',index=False)
    pd.DataFrame(feature_rows).to_csv(OUTPUT/'H_ddos_feature_shift.csv',index=False)
    pd.DataFrame(shap_rows).to_csv(OUTPUT/'H_ddos_shap.csv',index=False)
    write_json(OUTPUT/'H_method.json',{'populations':'simulation test TP/TN and CICIDS DDoS FN/benign TN; V2 and two V3 bundles',
        'features':'raw common forward features; KS finite values only, missingness retained in each population',
        'shap':'exact base DDoS XGBoost TreeSHAP log-odds with additivity available from booster; excludes meta attribution',
        'orientation':'auc_inverted is diagnostic only; no production score was flipped',
        'external':'CICIDS is a development benchmark after V3 was motivated by it'})
    print(json.dumps(orientation,indent=2,default=lambda v: v.item() if isinstance(v,np.generic) else v.tolist()),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['audit','ablation','adaptation','v3','plots','thresholds','ddos'], default='audit')
    args=parser.parse_args()
    torch.set_num_threads(2)
    OUTPUT.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    globals()[{'audit':'audit','ablation':'ablation','adaptation':'adaptation','v3':'v3','plots':'plots','thresholds':'threshold_sweep','ddos':'ddos_diagnosis'}[args.stage]]()
    print(f'{args.stage} completed in {time.monotonic()-started:.1f}s',flush=True)


if __name__=='__main__': main()
