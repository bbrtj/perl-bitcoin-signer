#!/usr/bin/env perl

use v5.40;
use autodie;
use lib 't/lib';

use Bitcoin::Crypto qw(btc_utxo btc_transaction);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants qw(:bip44);
use SignerTest::Fixtures qw(test_mnemonics);

# This is a script to used to generate xml file for tests

my $mnemonic_fixture = 0;
my $mnemonic_account = 1;
my $data = test_mnemonics($mnemonic_fixture, $mnemonic_account);
my $prev_key = $data->{account_keys}{$mnemonic_account}{(BIP44_COMPAT_PURPOSE)};
my $this_key_taproot = $data->{account_keys}{$mnemonic_account}{(BIP44_TAPROOT_PURPOSE)};
my $this_key_segwit = $data->{account_keys}{$mnemonic_account}{(BIP44_SEGWIT_PURPOSE)};

my $utxo = btc_utxo->new(
	txid => [hex => '12c28f81ba96c49ef5299c14074f3c82fd0e455ebe80efc10cf69cc440fa64a2'],
	output_index => 0,
	output => {
		locking_script => [
			address =>
				$prev_key->derive_key_bip44(get_from_account => true)->get_basic_key->get_public_key->get_address
		],
		value => 1e5,
	},
);

my $value_sent = int($utxo->output->value * 0.45);
my $fee_rate = 0.1;
my $tx = btc_transaction->new;

$tx->add_input(utxo => $utxo);

$tx->add_output(
	locking_script => [
		address => $this_key_taproot
			->derive_key_bip44(get_from_account => true, index => 3)
			->get_basic_key
			->get_public_key
			->get_address
	],
	value => $value_sent,
);

$tx->add_output(
	locking_script => [
		address => $this_key_segwit
			->derive_key_bip44(get_from_account => true, index => 2)
			->get_basic_key
			->get_public_key
			->get_address
	],
	value => $value_sent,
);

$tx->set_rbf;
$tx->sign(signing_index => 0, compat => true)
	->add_signature($prev_key->derive_key_bip44(get_from_account => true)->get_basic_key)
	->finalize;

# Same fee calculation technique as used
my $excess_fee = $tx->virtual_size * ($tx->fee_rate - $fee_rate);
$tx->add_output(
	locking_script => [
		address => $this_key_taproot
			->derive_key_bip44(get_from_account => true, change => 1, index => 4)
			->get_basic_key
			->get_public_key
			->get_address
	],
	value => 0,
);

$tx->outputs->[-1]->set_value(int($excess_fee - (length($tx->outputs->[-1]->to_serialized) * $fee_rate)));

$tx->sign(signing_index => 0, compat => true)
	->add_signature($prev_key->derive_key_bip44(get_from_account => true)->get_basic_key)
	->finalize;

# fee calculated

$tx->verify_standard;
say $tx->dump;

my $transaction_xml = sprintf join('', <DATA>),
	$fee_rate,
	$utxo->output_index,
	to_format [hex => $utxo->txid],
	$value_sent,
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
	<fee_rate>%s</fee_rate>
	<inputs>
		<input index="%s">%s</input>
	</inputs>
	<outputs>
		<output value="%s" type="taproot">new_address</output>
		<output value="%s">new_address</output>
		<output value="change" type="taproot">new_change</output>
	</outputs>

	<skip_addresses type="segwit">2</skip_addresses>
	<skip_addresses type="taproot">3</skip_addresses>
	<skip_change type="taproot">4</skip_change>

	<meta>
		<prop name="prevouts">%s</prop>
		<prop name="mnemonic_fixture">%s</prop>
		<prop name="mnemonic_account">%s</prop>
		<prop name="tx_hex">%s</prop>
	</meta>
</transaction>

