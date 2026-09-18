from ..contracts import ContractError


def require_major_version(payload, field, major=2):
    value = payload.get(field)
    if not isinstance(value, str) or not value.split(".", 1)[0].isdigit() or int(value.split(".", 1)[0]) != major:
        raise ContractError(f"{field} major version {major} required")
    return value


def check_observation_versions(payload):
    require_major_version(payload, "schema_version", 2)
    require_major_version(payload, "feature_schema_version", 2)
    return True
