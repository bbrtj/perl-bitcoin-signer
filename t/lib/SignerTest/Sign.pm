package SignerTest::Sign;

use v5.40;

use Mooish::Base;

use Bitcoin::Crypto qw(btc_utxo);
use Bitcoin::Crypto::Constants qw(:bip44);
use Bitcoin::Crypto::Transaction::Output;

has param 'master_key' => (
	isa => InstanceOf ['Bitcoin::Crypto::Key::ExtPrivate'],
);

has param 'account' => (
	isa => PositiveOrZeroInt,
);

with 'Signer::Role::ReadsScripts';

sub extpub_segwit ($self)
{
	return $self->master_key->derive_key_bip44(
		get_account => true,
		account => $self->account,
		purpose => BIP44_SEGWIT_PURPOSE,
	)->get_public_key;
}

sub extpub_taproot ($self)
{
	return $self->master_key->derive_key_bip44(
		get_account => true,
		account => $self->account,
		purpose => BIP44_TAPROOT_PURPOSE,
	)->get_public_key;
}

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

