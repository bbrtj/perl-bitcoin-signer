package Signer::Role::HasMasterKey;

use v5.38;

use Moo::Role;

requires qw(
	config
	input
);

sub master_key ($self, $purpose)
{
	my $cfg = $self->config;
	return btc_extprv
		->from_mnemonic($cfg->{master_key}, $self->input->password)
		->derive_key_bip44(
			get_account => 1,
			purpose => $purpose,
			account => $cfg->{account},
		);
}

