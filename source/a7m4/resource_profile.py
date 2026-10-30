"""One finite device scope; legacy archive inventories remain separate."""
ID = 'm4-602-six-language/1'
CAPTURE_SCHEMA = 'a7m4-toolbox-usb-backup/2'
ARCHIVE_SCHEMA = 'a7m4-backup/2'
ARCHIVE_SCOPE = 'm4-602-six-language-backup/1'
LANGUAGES = ('english', 'simplifiedchinese', 'traditionalchinese')
STRINGS = tuple(sorted('string_%s_%s.uxc' % (language, direction)
    for language in LANGUAGES for direction in ('horizontal', 'vertical')))
IMAGES = ('image_00_23_IPSX.uxc', 'image_00_32_IPSX.uxc')
RESOURCES = tuple(sorted((*STRINGS, *IMAGES)))
RESOURCE_PATHS = tuple('/usr/share/app/' + name for name in RESOURCES)
OBJECTS = {
    'appFw.so': dict(target_path='/usr/lib/appFw.so', kind='ap'),
    'CPAPP-B.BIN': dict(target_path='/cp/CPAPP-B.BIN', kind='cp'),
    **{'resources/' + name: dict(target_path='/usr/share/app/' + name, kind='resource') for name in RESOURCES},
    'extras/SysSound.bin': dict(target_path='/cp/SysSound.bin', kind='audio'),
}
COUNT = len(OBJECTS)
READ_PATHS = frozenset(row['target_path'] for row in OBJECTS.values())
assert len(STRINGS) == 6 and len(RESOURCES) == 8 and COUNT == 11


def capture_definitions(receipt, legacy):
    schema = receipt.get('schema')
    if schema == CAPTURE_SCHEMA and receipt.get('resource_profile') == ID:
        return OBJECTS
    if schema == 'a7m4-toolbox-usb-backup/1' and 'resource_profile' not in receipt:
        return dict(legacy, **{'extras/SysSound.bin': OBJECTS['extras/SysSound.bin']})
    raise ValueError('Unknown capture schema/resource scope combination')
