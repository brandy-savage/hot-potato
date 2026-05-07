# Re-export shim for backwards compatibility.
# New code: `import hot_potato` or `from hot_potato import safe_fetch`
from hot_potato import *  # noqa: F401, F403
from hot_potato import safe_fetch, scan_file, scan_repo, scan_skills_dir, setup, HotPotatoResult  # noqa: F401
