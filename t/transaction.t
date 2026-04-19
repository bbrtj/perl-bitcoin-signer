use v5.40;
use Test2::V1 -ipP;
use lib 't/lib';

use Bitcoin::Crypto::Constants qw(:bip44);
use Signer::ClientScripts;
use Signer::Transaction;
use SignerTest::Fixtures qw(test_mnemonics);
use SignerTest::Sign;

################################################################################
# This tests whether Transaction module works - specifically get_tx.
# Transaction fixture data is loaded from t/transactions
################################################################################

my $case = 0;
my $client_scripts = Signer::ClientScripts->new(directory => "t/transactions/$case");
my $meta = $client_scripts->head->{state}{meta};
my $key_data = test_mnemonics($meta->{mnemonic_fixture}, $meta->{mnemonic_account});
my $extprv = $key_data->{account_keys}{$meta->{mnemonic_account}}{(BIP44_SEGWIT_PURPOSE)};

my $sign = SignerTest::Sign->new(
	client_scripts => $client_scripts,
	extprv => $extprv,
);

my %args = $sign->get_last_script_args->%*;
my $module = Signer::Transaction->new(
	input => {
		password => $key_data->{mnemonic_password},
		%args,
	}
);

$module->set_config_keys(
	master_key => $key_data->{mnemonic},
	account => $meta->{mnemonic_account},
);

################################################################################

subtest 'get_tx should produce a signed transaction' => sub {
	my $tx = $module->get_tx;

	isa_ok $tx, 'Bitcoin::Crypto::Transaction';
	is unpack('H*', $tx->to_serialized), $meta->{tx_hex}, 'serialized tx matches expected';
};

subtest 'get_tx self_outputs should belong to this master key' => sub {
	my $tx = $module->get_tx;

	for my $output ($tx->outputs->@*) {
		my $address = $output->locking_script->get_address;

		ok lives { $module->find_key($address) }, "address $address belongs to master key";
	}
};

done_testing;

