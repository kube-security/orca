package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	_ "github.com/mattn/go-sqlite3"
	_ "modernc.org/sqlite"
)

type PackageInfo struct {
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Author    string   `json:"author"`
	Files     []string `json:"files"`
	SourceRpm string   `json:"rpm"`
}

func main() {

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: rpm_checker -dbpath=<path_to_rpm_database>")
		fmt.Println("Example: rpm_checker -dbpath=./Packages")
		return
	}
	// Define flags for the database path and package names
	dbPath := flag.String("dbpath", "./Packages", "Path to the RPM database")
	flag.Parse()

	if err := run(*dbPath); err != nil {
		log.Fatal(err)
	}
}

func run(dbPath string) error {
	db, err := rpmdb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	packages := []PackageInfo{}
	pkgList, err := db.ListPackages()
	if err != nil {
		return err
	}

	for _, pkg := range pkgList {
		files := []string{}
		fileinfo, _ := pkg.InstalledFiles()

		for _, f := range fileinfo {
			files = append(files, f.Path[1:])
		}

		packages = append(packages, PackageInfo{pkg.Name, pkg.Version, pkg.Vendor, files, pkg.SourceRpm})
	}
	res, _ := json.Marshal(packages)
	fmt.Println(string(res))
	return nil
}
