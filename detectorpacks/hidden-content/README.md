# privometry/hidden-content detector pack

Finds text a person reviewing a file would not see but an agent reads: zero-width and direction-changing characters (as in Trojan Source attacks), Unicode tag characters that spell hidden text, runs of variation selectors, private-use characters, instructions inside HTML comments, base64 blobs that decode to instructions, and text pushed off-screen by long mid-line gaps.

Findings set `hidden_content` and show the hidden text: invisible characters as `<U+XXXX>`, tag characters decoded.
