/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 * 
 * Rule Package Information
 * Name: core 
 * Description: V3LUM synthetic test package in the YARA Forge layout (not real YARA Forge content)
 * YARA-Forge Version: 0.0.0-test
 * YARA-QA Commit: 0000000000000000000000000000000000000000
 * Minimum Quality: 70
 * Force Include Importance Level: 80
 * Force Exclude Importance Level: 50
 * Minimum Age (in days): 1
 * Minimum Score: 65
 * Creation Date: 2026-11-26
 * Number of Rules: 8
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 */

import "pe"


/*
 * YARA Rule Set
 * Repository Name: V3LUM Test NoLicence
 * Repository: https://github.com/example/v3lum-test-rules-nolicence/
 * Retrieval Date: 2026-11-26
 * Git Commit: 3333333333333333333333333333333333333333
 * Number of Rules: 2
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 *
 *
 * LICENSE
 *
 * NO LICENSE SET
 */
private rule V3LUM_TEST_NOLICENCE_IsMZ_PRIVATE
{
	meta:
		description = "private helper without licence"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "N/A"
		score = 75

	condition:
		uint16(0) == 0x5A4D
}
rule V3LUM_TEST_NOLICENCE_Any_Marker
{
	meta:
		description = "rule without licence meta: never loaded"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		reference = "https://example.com/rules/nolicence"
		license_url = "N/A"
		score = 75

	strings:
		$m = "MARKER" ascii

	condition:
		$m
}

/*
 * YARA Rule Set
 * Repository Name: V3LUM Test MIT
 * Repository: https://github.com/example/v3lum-test-rules-mit/
 * Retrieval Date: 2026-11-26
 * Git Commit: 1111111111111111111111111111111111111111
 * Number of Rules: 3
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 *
 *
 * LICENSE
 *
 * MIT License
 *
 * Copyright (c) 2026 V3LUM test suite
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, subject to the following conditions: (synthetic test text)
 */
private rule V3LUM_TEST_MIT_IsSmall_PRIVATE
{
	meta:
		description = "private helper"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-mit/blob/1111111111111111111111111111111111111111/LICENSE"
		score = 75

	condition:
		filesize < 1MB
}
rule V3LUM_TEST_MIT_MAL_ExampleFam_Marker : FILE
{
	meta:
		description = "Detects the ExampleFam test marker (synthetic family rule)"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		reference = "https://example.com/rules/examplefam"
		source_url = "https://github.com/example/v3lum-test-rules-mit/blob/1111111111111111111111111111111111111111/examplefam.yar#L1-L20"
		license_url = "https://github.com/example/v3lum-test-rules-mit/blob/1111111111111111111111111111111111111111/LICENSE"
		malware_family = "Trojan:W32/ExampleFam"
		score = 80
		quality = 80
		tags = "FILE"

	strings:
		$marker = "V3LUM-EXAMPLEFAM-MARKER" ascii
		$re = /V3LUM-[A-Z]{3,12}-MARKER\{?/ ascii   // braces inside a regex
		$hex = { 56 33 4C 55 4D [1-4] 45 58 }      /* "V3LUM" .. "EX" in a hex string */

	condition:
		$marker and ( $re or $hex ) and V3LUM_TEST_MIT_IsSmall_PRIVATE
}
rule V3LUM_TEST_MIT_Uses_Unlicensed
{
	meta:
		description = "depends on an unlicensed private rule"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-mit/blob/1111111111111111111111111111111111111111/LICENSE"
		score = 75

	condition:
		V3LUM_TEST_NOLICENCE_IsMZ_PRIVATE and filesize < 10KB
}

/*
 * YARA Rule Set
 * Repository Name: V3LUM Test DRL
 * Repository: https://github.com/example/v3lum-test-rules-drl/
 * Retrieval Date: 2026-11-26
 * Git Commit: 2222222222222222222222222222222222222222
 * Number of Rules: 2
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 *
 *
 * LICENSE
 *
 * # Detection Rule License (DRL) 1.1
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set and associated
 * documentation files (the "Rules"), to deal in the Rules without restriction (synthetic test excerpt).
 */
rule V3LUM_TEST_DRL_SUSP_EICAR_Test_String
{
	meta:
		description = "EICAR anti-virus test string (generic test rule)"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		reference = "https://www.eicar.org/download-anti-malware-testfile/"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
		license_url = "https://github.com/example/v3lum-test-rules-drl/blob/2222222222222222222222222222222222222222/LICENSE"
		score = 60

	strings:
		$a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"   // a closing brace inside a text string
		$b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

	condition:
		$a at 0 and $b at 28
}
rule V3LUM_TEST_DRL_HKTL_Example_Tool
{
	meta:
		description = "hack tool test rule (generic by prefix)"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-drl/blob/2222222222222222222222222222222222222222/LICENSE"
		score = 75

	strings:
		$t = "V3LUM-HKTL-EXAMPLE" ascii

	condition:
		$t
}

/*
 * YARA Rule Set
 * Repository Name: V3LUM Test NC
 * Repository: https://github.com/example/v3lum-test-rules-nc/
 * Retrieval Date: 2026-11-26
 * Git Commit: 4444444444444444444444444444444444444444
 * Number of Rules: 1
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 *
 *
 * LICENSE
 *
 * Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) - synthetic test text
 */
rule V3LUM_TEST_NC_MAL_ExampleFam_NC
{
	meta:
		description = "non-commercial family rule"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license = "CC BY-NC 4.0"
		license_url = "https://github.com/example/v3lum-test-rules-nc/blob/4444444444444444444444444444444444444444/LICENSE"
		malware_family = "ExampleFam"
		score = 85

	strings:
		$m = "V3LUM-EXAMPLEFAM-MARKER" ascii

	condition:
		$m
}
