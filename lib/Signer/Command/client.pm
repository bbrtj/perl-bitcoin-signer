package Signer::Command::client;

use v5.38;

use Moo;
use Mooish::AttributeBuilder;

extends 'Mojolicious::Command';

has field 'description' => (
	default => sub {
		'Run signer client on hot device',
	},
);

has field 'usage' => (
	default => sub ($self) {
		$self->extract_usage,
	},
);

sub run ($self, @args)
{

}

__END__

=head1 SYNOPSIS

  Usage: APPLICATION client [CLIENT_SCRIPT]

  Needs signer_host and signer_port configured in signer.yml.

