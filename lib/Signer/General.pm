package Signer::General;

use v5.40;
use Mooish::Base;
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Constants ':bip44';

use Signer::Input;

has param 'parent' => (
	isa => InstanceOf ['Signer'],
	handles => {
		config => 'signer_config',
	},
);

has param 'input' => (
	coerce => (InstanceOf ['Signer::Input'])
		->plus_coercions(HashRef, q{ Signer::Input->new($_) }),
);

with qw(Signer::Role::HasMasterKey);

sub get_pubs ($self)
{
	my @purposes = (
		BIP44_PURPOSE,
		BIP44_COMPAT_PURPOSE,
		BIP44_SEGWIT_PURPOSE,
		BIP44_TAPROOT_PURPOSE
	);

	my @pubs = map {
		to_format [base58 => $self->master_key($_)->get_public_key->to_serialized]
	} @purposes;

	return \@pubs;
}

