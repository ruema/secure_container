#!/usr/bin/python3
import sys
import os
import time
import json
import uuid
import subprocess
import argparse
import ctypes
import ctypes.util
from pathlib import Path
import crypt_fs

BASE_PATH = Path(__file__).parent.absolute()
NAMESPACES = ["pid", "ipc", "uts"]

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000

_PATH_PROC_UIDMAP = "/proc/self/uid_map"
_PATH_PROC_GIDMAP = "/proc/self/gid_map"
_PATH_PROC_SETGROUPS = "/proc/self/setgroups"

def setgroups_control(cmd):
    with open(_PATH_PROC_SETGROUPS, 'w') as fd:
        fd.write(cmd)

def map_id(filename, id_from, id_to):
    with open(filename, "w") as fd:
        fd.write(f"{id_from} {id_to} 1")

def unshare_mount():
    real_euid = os.geteuid()
    real_egid = os.getegid()
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if _libc.unshare(CLONE_NEWUSER|CLONE_NEWNS):
        raise RuntimeError("unshare failed")
    setgroups_control("deny")
    map_id(_PATH_PROC_UIDMAP, 0, real_euid)
    map_id(_PATH_PROC_GIDMAP, 0, real_egid)

def need_layer(layer):
    path = BASE_PATH / 'work_layers' / layer.replace(':', '_')
    if not path.is_dir():
        path.mkdir(parents=True)
        layerpath = BASE_PATH / 'layers' / layer
        subprocess.run(['tar', '-xf', layerpath], check=False, cwd=path)

def store_layer(path):
    layerpath = BASE_PATH / 'layers' / str(uuid.uuid4())
    upper = path / 'ovl' / 'upper'
    filenames = [f.name for f in upper.iterdir()]
    subprocess.run(['tar', '-czf', layerpath] + filenames, check=False, cwd=upper)
    sha = subprocess.run(['sha256sum', '-b', layerpath], stdout=subprocess.PIPE)
    sha = sha.stdout.split()[0].decode('ASCII')
    layerpath.rename(layerpath.parent / f'sha265:{sha}')
    return f'sha265:{sha}'


def push_image(run_name, name, tag):
    path = BASE_PATH / 'runtime' / run_name
    layer = store_layer(path)
    with open(path / 'config.json', 'r', encoding='utf8') as input:
        config = json.load(input)
    env = dict(c.split('=',1) for c in config["process"]["env"])
    parent_name = env["container_bname"]
    parent_tag = env["container_tag"]

    manifest = Path(BASE_PATH) / 'images' / parent_name / parent_tag
    with open(manifest, encoding='utf8') as lines:
        manifest = json.load(lines)
    mani_config = json.loads(manifest['history'][0]['v1Compatibility'])

    architecture = manifest['architecture']
    layers = manifest['fsLayers']
    layers.append({"blobSum": layer})
    history = manifest['history']

    manifest = {
        "schemaVersion": 1,
        "name": name,
        "tag": tag,
        "architecture": architecture,
        "fsLayers": layers,
        "history": history
    }
    
    filename = Path(BASE_PATH) / 'images' / name / tag
    filename.parent.mkdir(parents=True)
    with open(filename, 'w', encoding='utf8') as output:
        json.dump(output, manifest)

def create_runimage(name, tag, net=False, work_path=None, encrypt=False, password=""):
    run_name = str(uuid.uuid4())
    print(f"Create image {run_name}.")
    path = BASE_PATH / 'runtime' / run_name
    manifest = Path(BASE_PATH) / 'images' / name / tag
    with open(manifest, encoding='utf8') as lines:
        manifest = json.load(lines)
    mani_config = json.loads(manifest['history'][0]['v1Compatibility'])
    need_layer('ROOT')
    for layer in manifest['fsLayers']:
        need_layer(layer["blobSum"])
    mount_path = path / 'mnt'
    ovl_path = path / 'ovl'
    pipein, pipeout = os.pipe()
    pid = os.fork()
    if not pid:
        os.close(pipein)
        unshare_mount()
        mount_path.mkdir(parents=True)
        if encrypt:
            ovl_path.mkdir()
            secure_fs = crypt_fs.SecureFs()
            if password:
                with open(path / 'encrypt.json', 'w') as cfg:
                    json.dump(secure_fs.generate_config(password), cfg)
            enc_path = path / 'enc'
            enc_path.mkdir()
            subprocess.run([
                str(BASE_PATH / 'tools' / 'securefs'),
                "mount", "-b",
                "--config", "/dev/stdin",
                "--log", "/dev/null",
                "--pass", "password",
                str(enc_path),
                str(ovl_path)
            ], input=json.dumps(secure_fs.generate_config("password",
                crypt_fs.PBKDF_ALGO_PKCS5, rounds=1)).encode())
        layers = ':'.join(
            str(BASE_PATH / 'work_layers' / '{}'.format(l["blobSum"].replace(':','_')))
            for l in reversed(manifest['fsLayers'])
        )
        upper_path = ovl_path / 'upper'
        work_path = ovl_path / 'work'
        upper_path.mkdir(parents=True)
        work_path.mkdir()
        subprocess.run([
            str(BASE_PATH / 'tools' / 'fuse-overlayfs'),
            "-o", f"lowerdir={layers},upperdir={upper_path},workdir={work_path}",
            str(mount_path)
        ])
        os.write(pipeout, b'x')
        time.sleep(9999)
        sys.exit()
    os.close(pipeout)
    # wait for mounts
    _ = os.read(pipein, 1)
    with open(BASE_PATH / 'config' / 'config.json', encoding='utf8') as lines:
        config = json.load(lines)
    config["linux"]["uidMappings"][0]["hostID"] = os.getuid()
    config["linux"]["gidMappings"][0]["hostID"] = os.getgid()
    config["linux"]["namespaces"] = [
        {"type": "mount", "path": f"/proc/{pid}/ns/mnt"},
        {"type": "user", "path": f"/proc/{pid}/ns/user"},
    ] + [
        {"type": ns} for ns in NAMESPACES if not net or ns != 'ipc'
    ]
    config["process"]["args"] = mani_config["config"]["Cmd"]
    config["process"]["env"] = mani_config["config"]["Env"] + [
        f"container_name={name}", f"container_tag={tag}",
    ]
    config["root"] = {"path": str(mount_path), "readonly": False}
    config["mount"].append({
        "source": Path(work_path).absolute(),
        "type": "bind",
        "destination": "/work",
    })
    with open(path / 'config.json', 'w', encoding='utf8') as output:
        json.dump(config, output)
    return path

def main():
    parser = argparse.ArgumentParser(description='Run container.')
    parser.add_argument('name', help='image name')
    parser.add_argument('tag', help='image tag')
    parser.add_argument('--net', action='store_true', default=False, help='use host network')
    parser.add_argument('--encrypt', action='store_true', default=False, help='encrypt upper layer')
    parser.add_argument('--password', help="password for encryption")
    parser.add_argument('--work-path', help="mount point /work")
    args = parser.parse_args()

    path = create_runimage(args.name, args.tag, args.net, args.work_path, args.encrypt, args.password)
    subprocess.run([
        str(BASE_PATH / 'tools' / 'runc-x86_64'),
        '--root', path, 'run', '--no-pivot',
        '--bundle', path, path.name])

if __name__ == '__main__':
    main()