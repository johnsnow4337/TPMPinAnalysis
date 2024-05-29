---- 010 Editor Template Instructions ----

To use the 010 Editor Template *BitlockerMetadata.bt* install 010 editor, open the Bitlocker metadata files under ./Data/Just*.dat

NOTE: The metadata under ./Data/Just*.dat only includes relevant areas of metadata, excluding the second and third copy of FVE metadata and replacing the first metadata offset in the boot header with 0x210

---- Ghidra Analysis Viewing Instructions ----

To view the reverse-engineering in Ghidra, install Ghidra. View the Ghidra project via File -> New Project, then viewing project with Project -> View Project opening *manage-bde.gpr*.
