# Community packs: NDTi18n.<lang>.json (e.g., NDTi18n.de.json). The stem is a
# constant and not built from $AppNameShort, so a pack survives a rename.
function Resolve-I18nFilePath([string]$Lang) { Join-Path $HereDir ("i18n\NDTi18n.{0}.json" -f $Lang) }
