package tlproc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KyleBanks/depth"
	"github.com/stretchr/testify/require"
)

const embeddedPkg = "github.com/getlantern/trafficlog-flashlight/internal/tlserverbin"

var embeddedCommands = []string{
	"github.com/getlantern/trafficlog-flashlight/internal/cmd/tlserver",
	"github.com/getlantern/trafficlog-flashlight/internal/cmd/tlconfig",
	"github.com/getlantern/trafficlog-flashlight/internal/cmd/config-bpf",
}

// If one of the commands embedded in the tlserverbin package ends up importing the tlserverbin
// package (directly or indirectly), we get an import cycle of sorts. The Go tool and go-bindata
// will happily support this, but the embedded binaries will grow each time they are re-built. This
// test checks for such import cycles to avoid this case.
func TestImportCycles(t *testing.T) {
	for _, cmd := range embeddedCommands {
		tr := depth.Tree{MaxDepth: 10}
		require.NoError(t, tr.Resolve(cmd))
		importsEmbedded, p := search(*tr.Root, func(p depth.Pkg) bool { return p.Name == embeddedPkg })
		if importsEmbedded {
			t.Fatal(fmt.Sprint("forbidden import of embedded package by embedded command\n", fmtImportPath(*p)))
		}
	}
}

// search the tree for any node satisfying the predicate. Returns the first such node found.
func search(root depth.Pkg, predicate func(p depth.Pkg) bool) (found bool, p *depth.Pkg) {
	for _, dep := range root.Deps {
		found, p = search(dep, predicate)
		if found {
			return
		}
	}
	if predicate(root) {
		return true, &root
	}
	return false, nil
}

func fmtImportPath(imported depth.Pkg) string {
	if imported.Parent == nil {
		panic("no path to imported package")
	}
	path := []string{}
	current := &imported
	for current != nil {
		path = append(path, current.Name)
		current = current.Parent
	}
	b := new(strings.Builder)
	for i := len(path) - 1; i > 0; i-- {
		fmt.Fprintf(b, "%s imports\n", path[i])
	}
	fmt.Fprint(b, path[0])
	return b.String()
}
