// Package netnsutil runs functions inside a named network namespace,
// with a shell-out fallback for creating namespaces when the native
// bind-mount route is unavailable (e.g. restricted /run/netns).
package netnsutil

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/vishvananda/netns"
)

// CreateNamed creates the named namespace (idempotent).
func CreateNamed(name string) (netns.NsHandle, error) {
	if h, err := netns.GetFromName(name); err == nil {
		return h, nil
	}
	h, err := netns.NewNamed(name)
	if err == nil {
		return h, nil
	}
	// Fallback: let iproute2 do it (it applies its own mount tricks).
	if out, e2 := exec.Command("ip", "netns", "add", name).CombinedOutput(); e2 != nil {
		return -1, fmt.Errorf("create netns %s: native: %v; ip netns: %v (%s)", name, err, e2, out)
	}
	return netns.GetFromName(name)
}

// DeleteNamed removes the named namespace (idempotent).
func DeleteNamed(name string) error {
	if err := netns.DeleteNamed(name); err == nil {
		return nil
	}
	out, err := exec.Command("ip", "netns", "del", name).CombinedOutput()
	if err != nil {
		// Already gone is fine.
		if _, gerr := netns.GetFromName(name); gerr != nil {
			return nil
		}
		return fmt.Errorf("delete netns %s: %v (%s)", name, err, out)
	}
	return nil
}

// WithNetNS runs fn with the calling goroutine's OS thread bound to the
// named namespace, restoring the original namespace afterwards. Use it
// for operations the kernel resolves in the caller's namespace: BPF link
// creation (tcx attach) and wgctrl genetlink sockets.
func WithNetNS(name string, fn func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("save current netns: %w", err)
	}
	defer orig.Close()

	target, err := netns.GetFromName(name)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", name, err)
	}
	defer target.Close()

	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter netns %s: %w", name, err)
	}
	defer func() {
		if serr := netns.Set(orig); serr != nil && err == nil {
			err = fmt.Errorf("restore netns: %w", serr)
		}
	}()
	return fn()
}
