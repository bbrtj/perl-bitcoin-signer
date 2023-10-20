package Signer::General;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Types::Common qw(InstanceOf HashRef);
use Bitcoin::Crypto::Util qw(to_format);

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

sub get_pubs ($self)
{
	my @purposes = qw(44 49 84);
	my @pubs = map {
		to_format [base58 => $self->master_key($_)->get_public_key->to_serialized]
	} @purposes;

	return \@pubs;
}

