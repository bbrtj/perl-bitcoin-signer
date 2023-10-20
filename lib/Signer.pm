package Signer;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Mojo::JSON qw(decode_json);
use Try::Tiny;
use Bitcoin::Crypto::Util qw(to_format);

use Signer::Transaction;
use Signer::General;

extends 'Mojolicious';

with 'Signer::Role::HasConfig';

sub startup ($self)
{
	$self->secrets($self->signer_config->{secrets});
	push @{$self->commands->namespaces}, 'Signer::Command';

	my $r = $self->routes;

	$r->post('/sign' => sub ($c) {
		return $self->sign($c);
	});

	$r->post('/pubs' => sub ($c) {
		return $self->pubs($c);
	});
}

sub sign ($self, $c)
{
	my $tx;
	my $error;
	try {
		my $signer = Signer::Transaction->new(
			parent => $self,
			input => scalar decode_json($c->req->body),
		);

		$tx = $signer->get_tx();
	}
	catch {
		$error = $_;
	};

	my $success = !defined $error;
	return $c->render(json => {
		status => $success,
		($success
			? (result => to_format [hex => $tx->to_serialized])
			: (error => $error)
		),
	});
}

sub pubs ($self, $c)
{
	my $pubs;
	my $error;
	try {
		my $gen = Signer::General->new(
			parent => $self,
			input => scalar decode_json($c->req->body),
		);

		$pubs = $gen->get_pubs;
	}
	catch {
		$error = $_;
	};

	my $success = !defined $error;
	return $c->render(json => {
		status => $success,
		($success
			? (result => $pubs)
			: (error => $error)
		),
	});
}

