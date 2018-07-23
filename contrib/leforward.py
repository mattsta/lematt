#!/usr/bin/env python3

""" Run a single-purpose HTTP server.

Server takes all GET requests and redirects them to a new host
if the request URI starts with SUBPATH, otherwise returns 404.

Requests are redirected to the URL provided by --baseurl. """

import socketserver
import http.server
import argparse
import sys


CHALLENGE_HOST = None
SUBPATH = "/.well-known/acme-challenge"


class RedirectChallenges(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith(SUBPATH):
            self.send_response(301)
            self.send_header('Location', f"{CHALLENGE_HOST}{self.path}")
        else:
            self.send_response(404)

        self.end_headers()


class ReusableServer(socketserver.TCPServer):
    """ Allow TCPServer to reuse host address.

    Without setting 'allow_reuse_address', we can get stuck in
    TIME_WAIT after being killed and the stale state stops a new
    server from attaching to the port."""

    allow_reuse_address = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Redirect all URIs with matching prefix to another host")
    parser.add_argument(
        '--baseurl',
        dest='baseurl',
        required=True,
        help="Destination URL for all matching URIs on this server")

    args = parser.parse_args()
    CHALLENGE_HOST = args.baseurl

    if not CHALLENGE_HOST.startswith("http"):
        print("Redirect URL must be a full URL starting with http")
        sys.exit(1)

    # If user gave us a trailing slash URL, remove slash.
    if CHALLENGE_HOST[-1] == "/":
        CHALLENGE_HOST = CHALLENGE_HOST[:-1]

    serverAddress = ('', 80)

    # Note: if running remotely by an SSH command, you MUST launch with '-t':
    #   > ssh -t me@otherhost leforward.py --baseurl http://otherserver.com
    # If you omit '-t' the listening server won't terminate when you kill the
    # ssh session, which probably isn't what you want.
    with ReusableServer(serverAddress, RedirectChallenges) as httpd:
        httpd.serve_forever()

    # Production LE endpoints don't seem to disconnect nicely.
    # Python throws (non-terminal) errors of:
    # ConnectionResetError: [Errno 104] Connection reset by peer
