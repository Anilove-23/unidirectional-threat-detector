const express = require('express');
const { productStore } = require('../redis/subscriber');
const router = express.Router();

for (const [route, kind] of [['decisions', 'decision'], ['incidents', 'incident']]) {
  router.get(`/${route}`, (req, res) => {
    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);
    if (!Number.isInteger(limit) || limit < 1 || limit > 500 || !Number.isInteger(offset) || offset < 0) {
      return res.status(400).json({ status: 'error', message: 'Invalid pagination' });
    }
    res.json({ status: 'success', data: productStore.list(kind, { limit, offset, state: req.query.state, label: req.query.label }) });
  });
  router.get(`/${route}/:id`, (req, res) => {
    const data = (kind === 'decision' ? productStore.decisions : productStore.incidents).get(req.params.id);
    if (!data) return res.status(404).json({ status: 'error', message: 'Record not found' });
    res.json({ status: 'success', data });
  });
}
module.exports = router;
