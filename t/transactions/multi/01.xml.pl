#!/usr/bin/env perl

use v5.40;
use autodie;
use lib 't/lib';

use Bitcoin::Crypto qw(btc_utxo btc_transaction);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants qw(:bip44);
use SignerTest::Fixtures qw(test_mnemonics);

use Bitcoin::Secp256k1;
$Bitcoin::Secp256k1::FORCED_SCHNORR_AUX_RAND = "\x00" x 32;

# This is a script to used to generate xml file for tests

my $mnemonic_fixture = 0;
my $mnemonic_account = 1;
my $data = test_mnemonics($mnemonic_fixture, $mnemonic_account);
my $this_key = $data->{account_keys}{$mnemonic_account}{(BIP44_TAPROOT_PURPOSE)};
my $change_key = $data->{account_keys}{$mnemonic_account}{(BIP44_SEGWIT_PURPOSE)};

# hex of transaction 00
my $prev_tx = btc_transaction->from_serialized(
	[
		hex =>
			'0100000001a164fa40c49cf60cc1ef80be5e450efd823c4f07149c29f59ec496ba819fc212000000006a473044022030afaca1874e91293e4b5888add422a742af13816d1f441486c969187e6b018b022026dbc5bb4da7a342d69a32dbac688d8c056124540cbedd6097c190e0f8e9aa0d01210393b3389840dfff1ca3ad5c56f910a9264fc4afe453dbee3c0b225235a8c6f08afdffffff02905f010000000000225120fd238d2a9875fddfeb4508e4e0d5d6a9828eba8568a8e890ac32db69c23633280a1e000000000000160014f352ea7d3089ae16442be10bcc2f42e34bbdb75c00000000'
	]
);

$prev_tx->update_utxos;
my $prev_tx_hex_hash = to_format [hex => $prev_tx->txid];

my $value_sent = 96000;
my $tx = btc_transaction->new;

$tx->add_input(utxo => [[hex => $prev_tx_hex_hash], 0]);
$tx->add_input(utxo => [[hex => $prev_tx_hex_hash], 1]);

$tx->add_output(
	locking_script => [
		address => $this_key->derive_key_bip44(get_from_account => true, index => 1)
			->get_basic_key->get_public_key->get_address
	],
	value => $value_sent,
);

$tx->set_rbf;
$tx->sign(signing_index => 0)
	->add_signature($this_key->derive_key_bip44(get_from_account => true)->get_basic_key)
	->finalize;
$tx->sign(signing_index => 1)
	->add_signature($change_key->derive_key_bip44(get_from_account => true, change => true)->get_basic_key)
	->finalize;

# no change - no automatic fee

$tx->verify_standard;
say $tx->dump;

my $transaction_xml = sprintf join('', <DATA>),
	0,
	$prev_tx_hex_hash,
	1,
	$prev_tx_hex_hash,
	$value_sent,
	to_format [hex => join '', map { $_->utxo->output->to_serialized } $tx->inputs->@*],
	$mnemonic_fixture,
	$mnemonic_account,
	to_format [hex => $tx->to_serialized],
	;

my $filename = __FILE__ =~ s{.pl$}{}r;
open my $fh, '>', $filename;
print {$fh} $transaction_xml;

__DATA__
<?xml version="1.0" encoding="UTF-8"?>
<transaction>
	<inputs>
		<input index="%s">%s</input>
		<input index="%s">%s</input>
	</inputs>
	<outputs>
		<output value="%s" type="taproot">new_address</output>
	</outputs>

	<meta>
		<prop name="prevouts">%s</prop>
		<prop name="mnemonic_fixture">%s</prop>
		<prop name="mnemonic_account">%s</prop>
		<prop name="tx_hex">%s</prop>
	</meta>
</transaction>

