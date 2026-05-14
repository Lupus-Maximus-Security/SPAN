# Copyright 2025 Lupus Maximus LLC
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This is code for getting audit messages from remote systems and using
# them within span.

import uuid
import subprocess

from fabric import task, Connection

import sepolgen.audit as audit
from pandas import DataFrame

@task
def get_audit_messages(c: Connection):
    return c.sudo("cat /var/log/audit/audit.log", hide=True).stdout.strip()

@task
def get_audit_msg(c: Connection, audit_id: str):
    return c.sudo("ausearch --input-logs -i -a " + audit_id, hide=True).stdout.strip()

type_to_name = {
    0: "ALLOW",
    -6: "BADCOMPUTE",
    -5: "BADPERM",
    -2: "BADSCON",
    -4: "BADTCLASS",
    -3: "BADTCON",
    3: "BOOLEAN",
    6: "BOUNDS",
    4: "CONSTRAINT",
    1: "DONTAUDIT",
    -7: "NOPOLICY",
    5: "RBAC",
    2: "TERULE",
    -1: "UNKNOWN",
}

def av_to_dict(av):
    return {
        "src_type": av.src_type,
        "tgt_type": av.tgt_type,
        "obj_class": av.obj_class,
        "perms": av.perms,
        "xperms": av.xperms,
        "type": type_to_name[av.type],
        "names": {x.name for x in av.audit_msgs if x != ""},
        "audit_msgs": [x.audit_id for x in av.audit_msgs][:5],
    }


@task
def get_audit(c: Connection):
    parser = audit.AuditParser()
    parser.parse_string(get_audit_messages(c))
    avs = [av_to_dict(x) for x in parser.to_access()]
    df = DataFrame(avs)
    return df

@task
def print_audit(c: Connection):
    print(get_audit(c))

@task
def audit2allow(c, **kwargs):
    # This subprocess nonsense is to avoid copying all of the
    # output into a string and then passing that into audit2allow.
    # That is way too slow. This is much, much faster.
    aargs = []
    for k, v in kwargs.items():
        aargs.append(f"--{k}")
        aargs.append(v)
    a = subprocess.Popen(["audit2allow"] + aargs,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         text=True)
    
    
    c.sudo("cat /var/log/audit/audit.log", out_stream=a.stdin)
            
    out, err = a.communicate()

    return out

@task
def print_audit2allow(c, args=""):
    kwargs = dict(item.split("=") for item in args.split(",") if "=" in item)
    print(audit2allow(c, **kwargs))

@task
def get_policy(c, policy_type="targeted", policy_fname="policy.35", fname="policy.33"):
    tmp_path =  f"/tmp/fabric_transfer_{str(uuid.uuid4())}"
    
    c.sudo(f"cp /etc/selinux/{policy_type}/policy/{policy_fname} {tmp_path}")
    
    c.sudo(f"chown {c.user}:{c.user} {tmp_path}")
    
    c.get(tmp_path, fname)
    
    c.sudo(f"rm {tmp_path}")


def connection_with_password(host, user, ssh_password=None, sudo_password=None):
    from fabric import Config
    from invoke.watchers import Responder

    overrides = {}

    if sudo_password is not None:
        # This watches for the sudo prompt and provides this password
        sudo_responder = Responder(pattern=r"\[sudo\] password for .*: ", response=f"{sudo_password}\n")
        overrides["sudo"] = {"watchers": [sudo_responder]}

    if ssh_password is not None:
        overrides["connect_kwargs"] = {"password": ssh_password}

    # This provides the password for both the ssh connection and the sudo -  you can do it
    # for one or both.
    my_config = Config(overrides=overrides)

    # Setup the connection with the config
    return Connection(host=host, user=user, config=my_config)
