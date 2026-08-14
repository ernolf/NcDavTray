# convenience setter to call when creating UI elements
function Apply-BrandIconToForm($form) { Ensure-AppBrandIcons; if ($script:AppIcon) { try { $form.Icon = $script:AppIcon } catch {} } }
