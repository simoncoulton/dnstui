"""Runs dnstui in a pty inside the terminal it is started in, and types a
scripted session into it with human-ish timing. Used by record.sh so the demo
is the real program, rendered by the real terminal.

usage: driver.py BINARY CONFIG_HOME GO_FILE DONE_FILE STOP_FILE PID_FILE
"""

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

binary, config_home, go_file, done_file, stop_file, pid_file = sys.argv[1:7]

# So the recorder can close the terminal if something goes wrong.
with open(pid_file, "w") as f:
    f.write(str(os.getppid()))

ENTER, ESC, CTRL_U = b"\r", b"\x1b", b"\x15"
DOWN, RIGHT = b"\x1b[B", b"\x1b[C"

# Wait for the recorder to be ready, then take the size Ghostty settled on.
deadline = time.time() + 60
while not os.path.exists(go_file):
    if time.time() > deadline:
        sys.exit("the recorder never signalled")
    time.sleep(0.02)
rows, cols = struct.unpack("HHHH", fcntl.ioctl(1, termios.TIOCGWINSZ, b"\0" * 8))[:2]

pid, fd = pty.fork()
if pid == 0:
    os.environ["XDG_CONFIG_HOME"] = config_home
    os.execv(binary, [binary])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def pump(seconds):
    """Relay the program's output to the terminal for a while."""
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.02)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            if data:
                os.write(1, data)


def press(keys, wait=0.6):
    os.write(fd, keys)
    pump(wait)


def type_text(text, delay=0.075):
    for ch in text:
        os.write(fd, ch.encode())
        pump(delay)


def query(text, wait):
    type_text(text)
    pump(0.35)
    press(ENTER, wait)


def new_query(text, wait):
    # `/` starts typing; Ctrl-U drops the previous target.
    press(b"/", 0.3)
    press(CTRL_U, 0.2)
    query(text, wait)


pump(1.6)                                   # welcome screen
query("mx:github.com", 2.6)
new_query("spf:github.com", 3.4)
new_query("dmarc:github.com", 2.6)
new_query("cert:github.com", 3.4)
new_query("whois:github.com", 5.2)
new_query("http:github.com", 4.0)

press(b"p", 1.0)                            # back through this session's results
press(b"p", 1.0)
press(b"p", 1.2)

press(b"T", 1.0)                            # theme picker, live preview
press(b"b", 1.2)                            # paint each theme's own background
for _ in range(6):                          # mocha, macchiato, latte, dracula, ...
    press(DOWN, 0.9)
press(ESC, 1.4)                             # cancel: nothing is saved

press(b"?", 2.6)                            # help
press(b"x", 1.0)
press(b"q", 0.4)
pump(0.3)

open(done_file, "w").close()
# Keep the window until the recorder has stopped, so it never sees it vanish.
deadline = time.time() + 30
while not os.path.exists(stop_file) and time.time() < deadline:
    time.sleep(0.05)
