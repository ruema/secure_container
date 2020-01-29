#!/usr/bin/python3
import sys
import os
import json
import uuid
import subprocess
from pathlib import Path
BASE_PATH=Path(__file__).parent.absolute()

START_SKRIPT = """#!/bin/sh
fuse-overlayfs -o lowerdir={},upperdir=/work/ovl_upper,workdir=/work/ovl_work /mnt
mount -t bind /proc /mnt/proc -o rbind
mount -t bind /dev /mnt/dev -o rbind
mount -t bind /sys /mnt/sys -o rbind
exec chroot /mnt "$@"
"""

def need_layer(layer):
    path = BASE_PATH / 'work_layers' / layer.replace(':', '_')
    if not path.is_dir():
        path.mkdir(parents=True)
        layerpath = BASE_PATH / 'layers' / layer
        subprocess.run(['tar', '-xf', layerpath], check=True, cwd=path)


def create_runimage(name, tag):
    run_name = str(uuid.uuid4())
    print(f"Create image {run_name}.")
    path = BASE_PATH / 'runtime' / run_name
    manifest = Path(BASE_PATH) / 'images' / name / tag
    with open(manifest, encoding='utf8') as lines:
        manifest = json.load(lines)
    need_layer('ROOT')
    for layer in manifest['fsLayers']:
        need_layer(layer["blobSum"])
    path.mkdir(parents=True)
    (path / 'ovl_upper').mkdir()
    (path / 'ovl_work').mkdir()
    with open(BASE_PATH / 'config' / 'config.json', encoding='utf8') as lines:
        config = json.load(lines)
    config["linux"]["uidMappings"][0]["hostID"] = os.getuid()
    config["linux"]["gidMappings"][0]["hostID"] = os.getgid()
    with open(path / 'config.json', 'w', encoding='utf8') as output:
        json.dump(config, output)
    with open(path / 'start.sh', 'w', encoding='utf8') as script:
        script.write(START_SKRIPT.format(
            ':'.join(
                '/layers/{}'.format(l["blobSum"].replace(':','_'))
                for l in reversed(manifest['fsLayers'])
            )
        ))
    (path / 'start.sh').chmod(0o755)
    return path

path = create_runimage(*sys.argv[1:])
subprocess.run([str(BASE_PATH / 'runc-x86_64'), '--root', path, 'run', '--bundle', path, path.name])
