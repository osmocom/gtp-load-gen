#! /usr/bin/python3

import sys
import argparse
from jinja2 import Template

def tunmap_pfcp_cfg(args):
        cfg_template = Template("""
pfcp-peer {{ upf.gtp_ip }}
 tx assoc-setup-req
 sleep 1
 end
{% for session in upf.sessions %}
pfcp-peer {{ upf.gtp_ip }}
 session tunmap {{session.teid}}
  gtp access teid local {{session.teid}} remote {{session.teid}}
  gtp access ip {{session.access_ip}}
  gtp core ip {{session.core_ip}}
  gtp core teid local {{session.core_teid}} remote {{session.core_teid}}
  tx session-est-req
  end
{% endfor %}
""")
        sessions = [ ]

        for context in range(args.ues):
                session = {
                'teid': 100 + context,
                'core_teid': 1000 + context,
                'core_ip': f'127.0.0.{context+1}',
                'access_ip': args.load_ip,
                }
                sessions.append(session)

        upf = {
                'gtp_ip': args.gtp_ip,
                'sessions': sessions
        }
        cfg = cfg_template.render(upf=upf)

        print(cfg)

def endecaps_pfcp_cfg(args):
        cfg_template = Template("""
pfcp-peer {{ upf.gtp_ip }}
 tx assoc-setup-req
 sleep 1
 end
{% for session in upf.sessions %}
pfcp-peer {{ upf.gtp_ip }}
 session endecaps {{session.teid}}
  ue ip {{session.ue_ip}}
  gtp access teid local {{session.teid}} remote {{session.teid}}
  gtp access ip {{session.access_ip}}
  tx session-est-req
  end
{% endfor %}
""")

        sessions = [ ]

        for context in range(args.ues):
                session = {
                'teid': 100 + context,
                'ue_ip': f'10.11.0.{context+1}',
                'access_ip': args.load_ip
                }
                sessions.append(session)

        upf = {
                'gtp_ip': args.gtp_ip,
                'sessions': sessions
        }
        cfg = cfg_template.render(upf=upf)

        print(cfg)

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--tunmap', action="store_true", help="Whether to use tunmap mode (default is en-/decaps)")
        parser.add_argument('-e', '--eps', type=int, default=1, help="Number of local EPs to connect from")
        parser.add_argument('-u', '--ues', type=int, default=1, help="Number of UEs")
        parser.add_argument('-f', '--flows', type=int, default=1, help="Number of Flows per UE")
        parser.add_argument('-g', '--gtp-ip', default="127.0.0.11", help="IP of the UPF to test")
        parser.add_argument('-l', '--load-ip', default="127.0.0.12", help="IP of gtp-load-test")

        args = parser.parse_args()

        if not args.tunmap:
                endecaps_pfcp_cfg(args)
        else:
                tunmap_pfcp_cfg(args)

        print("!===============gtp-load-gen============")

        print(f"!gtp-load-gen -e 1 -g 1 -t {args.ues} -f {args.flows} -T 100 -l {args.load_ip} -r {args.gtp_ip} -s 10.11.0.1 -d 10.12.0.1")
