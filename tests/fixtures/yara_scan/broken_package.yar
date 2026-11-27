/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 * 
 * Rule Package Information
 * Name: core 
 * Description: V3LUM synthetic broken package
 * YARA-Forge Version: 0.0.0-test
 * YARA-QA Commit: 0000000000000000000000000000000000000000
 * Minimum Quality: 70
 * Force Include Importance Level: 80
 * Force Exclude Importance Level: 50
 * Minimum Age (in days): 1
 * Minimum Score: 65
 * Creation Date: 2026-11-26
 * Number of Rules: 3
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 */

import "pe"
include "other_rules.yar"


/*
 * YARA Rule Set
 * Repository Name: V3LUM Test OK
 * Repository: https://github.com/example/v3lum-test-rules-mit/
 * Retrieval Date: 2026-11-26
 * Git Commit: 1111111111111111111111111111111111111111
 * Number of Rules: 1
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
rule V3LUM_TEST_OK_Marker
{
	meta:
		description = "valid rule"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-mit/blob/1111111111111111111111111111111111111111/LICENSE"
		score = 75

	strings:
		$m = "V3LUM-EXAMPLEFAM-MARKER"

	condition:
		$m
}

/*
 * YARA Rule Set
 * Repository Name: V3LUM Test Broken
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
rule V3LUM_TEST_BROKEN_Undefined_String
{
	meta:
		description = "uses an undefined string"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-drl/blob/2222222222222222222222222222222222222222/LICENSE"
		score = 75

	strings:
		$a = "abc"

	condition:
		$a and $undefined
}
rule V3LUM_TEST_BROKEN_Fine_Neighbour
{
	meta:
		description = "valid rule next to a broken one"
		author = "V3LUM test suite"
		date = "2026-11-26"
		modified = "2026-11-26"
		license_url = "https://github.com/example/v3lum-test-rules-drl/blob/2222222222222222222222222222222222222222/LICENSE"
		score = 75

	strings:
		$b = "V3LUM-HKTL-EXAMPLE"

	condition:
		$b
}
