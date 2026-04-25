use v5.40;
use Test2::V1 -ipP;
use lib 't/lib';

use Bitcoin::Crypto::Constants qw(:bip44);
use Signer::ClientScripts;
use Signer::Transaction;
use SignerTest::Fixtures qw(test_mnemonics);
use SignerTest::Sign;
use Mojo::JSON qw(encode_json decode_json);

use Bitcoin::Secp256k1;
$Bitcoin::Secp256k1::FORCED_SCHNORR_AUX_RAND = "\x00" x 32;

################################################################################
# This tests whether Transaction module works
# Transaction fixture data is loaded from t/transactions subdirectories
################################################################################

subtest 'testing whether find_key works' => sub {
	my $key_data = test_mnemonics(0, 0);

	my $module = Signer::Transaction->new(
		input => {
			password => $key_data->{mnemonic_password},
			inputs => [],
			outputs => [],
			fee_rate => 1,
		}
	);

	$module->set_config_keys(
		master_key => $key_data->{mnemonic},
		account => 0,
	);

	ok lives {
		my $source_key = $key_data->{account_keys}{0}{(BIP44_SEGWIT_PURPOSE)}
			->derive_key_bip44(
				get_from_account => true,
				index => 19
			)
			->get_basic_key
			;

		my $key = $module->find_key($source_key->get_public_key->get_address);

		is $key->to_serialized, $source_key->to_serialized, 'keys match ok';
	}, "good address ok";

	# random mempool segwit key
	ok dies { $module->find_key('bc1qjwmcc4nsvua0pqmuxe0vz2545lzuc7euerw93y') }, "bad address ok";
};

foreach my $case (
	qw(
		basic
		taproot
		skip
		multi
		nulldata
	)
	)
{
	subtest "should pass transaction test case $case" => sub {
		my $client_scripts = Signer::ClientScripts->new(directory => "t/transactions/$case");
		my $meta = $client_scripts->head->{state}{meta};
		my $key_data = test_mnemonics($meta->{mnemonic_fixture}, $meta->{mnemonic_account});

		my $sign = SignerTest::Sign->new(
			client_scripts => $client_scripts,
			master_key => $key_data->{master_key},
			account => $meta->{mnemonic_account},
		);

		# encode and decode args to simulate API behavior (makes sure no
		# illegal data is present)
		my %args = $sign->get_last_script_args->%*;
		my $args_coded = decode_json encode_json \%args;

		my $module = Signer::Transaction->new(
			input => {
				password => $key_data->{mnemonic_password},
				$args_coded->%*,
			}
		);

		$module->set_config_keys(
			master_key => $key_data->{mnemonic},
			account => $meta->{mnemonic_account},
		);

		subtest 'get_tx should produce a signed transaction' => sub {
			my $tx = $module->get_tx;

			isa_ok $tx, 'Bitcoin::Crypto::Transaction';
			is unpack('H*', $tx->to_serialized), $meta->{tx_hex}, 'serialized tx matches expected';
		};

		subtest 'get_tx self_outputs should belong to this master key' => sub {
			my $tx = $module->get_tx;

			for my $output_index ($module->input->self_outputs->@*) {
				my $output = $tx->outputs->[$output_index];
				my $address = $output->locking_script->get_address;

				ok lives { $module->find_key($address) }, "address $address belongs to master key";
			}
		};
	};
}

done_testing;

