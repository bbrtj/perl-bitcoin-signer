use v5.40;
use Test2::V1 -ipP;
use lib 't/lib';

use Bitcoin::Crypto::Util qw(to_format);
use Signer::General;
use SignerTest::Fixtures qw(test_mnemonics);

################################################################################
# This tests whether General module works
################################################################################

my $data = test_mnemonics(0, 1, 2);
my $module = Signer::General->new(input => {password => $data->{mnemonic_password}});
$module->set_config_keys(
	master_key => $data->{mnemonic},
	account => 1,
);

subtest 'should return proper extended public keys' => sub {
	is $module->get_pubs, get_expected_pubs(1), 'keys ok';
};

subtest 'should return proper keys even with whitespace mismatch' => sub {
	$module->set_config_keys(
		master_key => ' ' . $data->{mnemonic} . "\t",
	);

	is $module->get_pubs, get_expected_pubs(1), 'keys ok';
};

subtest 'should return different keys for a different account' => sub {
	$module->set_config_keys(account => 2);

	is $module->get_pubs, get_expected_pubs(2), 'keys ok';
};

subtest 'should restore original keys when switching back to account 1' => sub {
	$module->set_config_keys(account => 1);

	is $module->get_pubs, get_expected_pubs(1), 'keys ok';
};

done_testing;

sub get_expected_pubs ($account)
{
	my $account_keys = $data->{account_keys}{$account};

	return [
		map { to_format [base58 => $account_keys->{$_}->get_public_key->to_serialized] }
			sort keys $account_keys->%*
		],
		;
}

