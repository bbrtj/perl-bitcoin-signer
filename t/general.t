use v5.40;
use Test2::V1 -ipP;

use Signer::General;

################################################################################
# This tests whether General module works
################################################################################

my $mnemonic =
	'equal runway into girl sell clown marriage museum hurdle trim what service swift pulse adjust hover achieve burst bread fog maze cream because phone';
my @expected_keys = (
	'xpub6CwtigGwbWpSKmweXKuJtig2xELpNJtBDbw99nVYLuFf5o5ZCG3mgXu5TjH9y6vzyzbYRAWK2hs4BX4EHtm9rYeHq7Hi8gfgRkCumsy6qCx',
	'ypub6WcgpkNM4U49QHE5wMa2UJ5k4X7spTn4feKXC727TRshvquM7c8gKJpTKM5haDcosq87peisVtxFyENLKEg4Sz9s8L3QL6T9fmsK4kKRMpz',
	'zpub6rE37hKQ5qz3hLTVZVuhdMnTqHFx6JnAjUgBLgiEpRDEqEA5RtHLsRC5QaxWW8Mp4Mq6Yt4adYp73t49PKS7RRgkgWSmtegYAqR6Y5iKdvs',
	'xpub6BwZtsuE2aUCdqmp4PaKx6q7SMGmX7oZtoKKzKExGwKJMUiW8LpypgzWPKAMRhJDu7QSYSbw7DGMMy25XGnM2K7MZLHoszXFcEF4z4oniVT',
);

my $module = Signer::General->new(input => {password => 'test'});
$module->set_config_keys(
	master_key => $mnemonic,
	account => 1,
);

subtest 'should return proper extended public keys' => sub {
	is $module->get_pubs, \@expected_keys, 'keys ok';
};

subtest 'should return proper keys even with whitespace mismatch' => sub {
	$module->set_config_keys(
		master_key => " $mnemonic\t",
	);

	is $module->get_pubs, \@expected_keys, 'keys ok';
};

done_testing;

