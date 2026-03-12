package Signer::Role::HasMasterKey;

use v5.40;

use Mooish::Base -role;
use Bitcoin::Crypto qw(btc_extprv);

requires qw(
	signer_config
	input
);

sub master_key ($self, $purpose)
{
	return btc_extprv
		->from_mnemonic($self->signer_config->{master_key}, $self->input->password, 'en')
		->derive_key_bip44(
			get_account => 1,
			purpose => $purpose,
			account => $self->signer_config->{account},
		);
}

