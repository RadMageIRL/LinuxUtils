# logi-rx

Audit and tune a Logitech wireless receiver on Linux.

Wireless receiver problems on Linux tend to get misdiagnosed as range problems
when they are actually power-management or configuration problems. `logi-rx`
checks the settings that matter, fixes the ones it safely can, and gives you a
measurement tool for the ones it cannot — so you can tell an RF problem from a
software problem instead of guessing.

Standard library only. No dependencies.

## Quick start

```sh
./logi-rx.py                 # audit everything, change nothing
sudo ./logi-rx.py --apply    # apply runtime fixes + install persistent udev rule
./logi-rx.py --watch         # measure link quality empirically
sudo ./logi-rx.py --revert   # remove the udev rule
```

The default invocation is read-only. Nothing on your system changes unless you
pass `--apply`.

## What it checks

### USB topology

Reports which bus and root hub the receiver enumerated on, the host controller's
PCI address, and a table of every USB root hub with its speed and port count.

It explicitly **does not** claim to detect whether the physical port is USB 2 or
USB 3. It cannot, and neither can anything else reading sysfs: a full-speed HID
device always enumerates on the USB 2 companion bus, whether you plugged it into
a black port or a blue one. The two are indistinguishable from software. Use
`--watch` to test ports empirically instead.

This matters because USB 3 SuperSpeed signalling emits broadband noise into the
2.4 GHz band. A receiver in a USB 3 port, or on an extension cable routed
alongside a USB 3 cable or an external SSD, sits in a raised noise floor and
loses a meaningful chunk of its effective range.

### Kernel module

Verifies `hid_logitech_dj` is loaded or built in. Without it the receiver
presents as a single generic HID device, and per-device battery reporting and
pairing do not work.

### USB autosuspend

Checks `power/control` on the receiver. When the kernel is allowed to autosuspend
an input receiver, the first input after an idle period gets swallowed while the
device resumes. This reads as a dropped click or an ignored flick of the pointer
and is easy to mistake for a range problem. `--apply` sets it to `on`.

### USB remote wakeup

Checks `power/wakeup`. When disabled, the keyboard cannot resume the machine from
suspend — the classic complaint about Logitech media keyboards, and a settings
problem rather than a hardware limitation. `--apply` sets it to `enabled`.

If the device does not expose `power/wakeup` at all, it did not advertise
remote-wakeup capability and genuinely cannot resume the machine.

### ACPI controller wakeup

Resolves the receiver's parent xHCI controller and reports its `/proc/acpi/wakeup`
state. **This gates everything above** — if the controller is masked in ACPI, the
per-port `power/wakeup` setting you just enabled does nothing.

`logi-rx` deliberately will not change this for you. Writing a device name to
`/proc/acpi/wakeup` is a *toggle*, not a set, so a script that runs it twice
silently undoes its own work. There is no way to make it idempotent. The tool
reports the state and hands you the command:

```sh
echo XHC0 | sudo tee /proc/acpi/wakeup
```

Run it exactly once, then re-run `logi-rx` to confirm.

### Battery

Reads battery level directly from the `hidpp_battery` power-supply class. No
`solaar` required, though `solaar` is checked for and recommended since it is
useful for pairing and button remapping.

Not every device reports battery over HID++, including some K400 revisions. When
no reading is available the tool says so rather than inventing one.

Worth knowing regardless: falling alkaline voltage reduces transmit power well
before any low-battery indicator fires. If range degrades gradually over months,
swap cells before debugging RF. Lithium AA cells (Energizer L91) hold ~1.5 V
nearly flat to end of life and are worth it in a device you do not want to think
about.

### Persistent udev rule

Runtime sysfs writes are lost on reboot and on re-plug. `--apply` installs:

```
/etc/udev/rules.d/90-logitech-receiver.rules
```

The rule is generated against the *specific* vendor and product ID of the
detected receiver rather than matching all Logitech devices, so it will not
affect an unrelated webcam or headset. After writing it, the tool runs
`udevadm control --reload` and `udevadm trigger --subsystem-match=usb`.

`--revert` removes the rule. Runtime values stay as they are until the next
reboot or re-plug.

## Watch mode

```sh
./logi-rx.py --watch
./logi-rx.py --watch --duration 60 --gap-ms 50
```

Locates the pointer's evdev node via `/proc/bus/input/devices`, reads raw
`input_event` structs, and measures the gaps between motion events. Reports
median, p99, and worst gap, and prints each individual gap above the threshold
as it happens.

**Move the pointer continuously for the whole run.** A pause on your end is
indistinguishable from a dropout on the link's end.

The point is A/B testing. Run it from where you actually sit, move the receiver
to a different port or a different position, and run it again from the same spot:

- **Gap count drops a lot** — the old port or placement was the problem.
- **No change** — it is distance, transmit power, or 2.4 GHz congestion from
  your WiFi. Check whether your AP is sitting on an overlapping channel before
  blaming the hardware.
- **Clean run at your desk, bad run at the couch** — it is range, and no amount
  of configuration will fix it. The transmitter is the limit.

Exits nonzero when dropouts are found, so it scripts cleanly.

Needs read access to `/dev/input/event*`: either run with `sudo`, or add yourself
to the `input` group and log back in.

```sh
sudo usermod -aG input "$USER"
```

## Options

| Flag | Description |
|------|-------------|
| `--apply` | Apply fixes and install the udev rule. Requires root. |
| `--revert` | Remove the udev rule. Requires root. |
| `--watch` | Measure input-event gaps. |
| `--duration N` | Watch duration in seconds. Default 30. |
| `--gap-ms N` | Dropout threshold in milliseconds. Default 100. |
| `--device NAME` | Force a sysfs device node, e.g. `1-3`. |
| `--no-color` | Disable coloured output. |

When multiple Logitech devices are present the tool picks the most
receiver-looking one and tells you what else it found. Use `--device` to
override.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Checks completed, or watch found no dropouts |
| `1` | Nothing found, permission denied, or watch found dropouts |
| `2` | Not running on Linux |

## Notes

Detection does not depend on the built-in list of receiver product IDs being
complete — the list only ranks candidates when several Logitech devices are
attached. Any Logitech USB device can be targeted with `--device`.

The tool reads sysfs directly and does not shell out for its checks. The only
external commands it ever runs are `udevadm control --reload` and
`udevadm trigger`, both under `--apply` or `--revert`.
