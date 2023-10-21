package Signer::Role::HasMasterKey;

use v5.38;

use Moo::Role;
use Bitcoin::Crypto qw(btc_extprv);

requires qw(
	config
	input
);

sub master_key ($self, $purpose)
{
	return btc_extprv
		->from_mnemonic($self->config->{master_key}, $self->input->password)
		->derive_key_bip44(
			get_account => 1,
			purpose => $purpose,
			account => $self->config->{account},
		);
}

