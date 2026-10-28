package main

import "testing"

func TestClassifyLicense(t *testing.T) {
	tests := map[string]string{
		"Apache License\nVersion 2.0, January 2004":                                                                                  "Apache-2.0",
		"Mozilla Public License Version 2.0":                                                                                         "MPL-2.0",
		"Permission is hereby granted, free of charge, to any person obtaining a copy":                                               "MIT",
		"Redistribution and use in source and binary forms ... Neither the name of Example":                                          "BSD-3-Clause",
		"Redistribution and use in source and binary forms, with or without modification":                                            "BSD-2-Clause",
		"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee":                       "ISC",
		"This software is provided 'as-is', without any express or implied warranty. Altered source versions must be plainly marked": "Zlib",
		"all rights reserved": "",
	}
	for input, want := range tests {
		if got := classifyLicense(input); got != want {
			t.Errorf("classifyLicense(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGoPURL(t *testing.T) {
	if got, want := goPURL("example.com/mod/v2", "v2.3.4"), "pkg:golang/example.com/mod/v2@v2.3.4"; got != want {
		t.Fatalf("goPURL() = %q, want %q", got, want)
	}
}
