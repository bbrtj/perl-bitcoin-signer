package SignerTest::Sign;

use v5.40;

use Mooish::Base;

use Bitcoin::Crypto qw(btc_utxo);
use Bitcoin::Crypto::Transaction::Output;

has param 'extprv' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::ExtPrivate'],
);

with 'Signer::Role::ReadsScripts';

sub load_utxos ($self, $txid_hex)
{
	state $loaded = false;
	return if $loaded;

	my $head = $self->client_scripts->head;
	my $prevouts = $head->{tx}{meta}{prevouts};
	my $prevouts_pos = 0;

	foreach my $input ($head->{tx}{inputs}->@*) {
		my ($txid, $ind) = $input->{utxo}->@*;

		my $output = Bitcoin::Crypto::Transaction::Output->from_serialized(
			[hex => $prevouts],
			pos => \$prevouts_pos,
		);

		btc_utxo->new(
			txid => [hex => $txid],
			output_index => $ind,
			output => $output,
		)->register;
	}

	$loaded = true;
}

sub get_address ($self, $change, $index)
{
	return $self->extprv->derive_key_bip44(
		get_from_account => 1,
		change => $change,
		index => $index,
	)->get_basic_key->get_public_key->get_address;
}

