package Signer;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Try::Tiny;
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;

use Signer::Transaction;
use Signer::General;

extends 'Mojolicious';

with qw(
	Signer::Role::HasConfig
	Signer::Role::Checksums
);

sub startup ($self)
{
	$self->secrets($self->signer_config->{secrets});
	Bitcoin::Crypto::Network->get('bitcoin_testnet')->set_default
		unless fc $self->signer_config->{mode} eq fc 'production';

	push @{$self->commands->namespaces}, 'Signer::Command';

	my $r = $self->routes;

	$r->post('/sign' => sub ($c) {
		return $self->run_with_body($c, 'sign');
	});

	$r->post('/pubs' => sub ($c) {
		return $self->run_with_body($c, 'pubs');
	});
}

sub run_with_body ($self, $c, $func)
{
	my $returned;
	my $error;
	try {
		my $pwd = $self->signer_config->{password};
		my $body = $self->decode_body($pwd, $c->req->body);

		$returned = $self->$func($c, $body);
	}
	catch {
		$error = $_;
	};

	my $success = !defined $error;
	return $c->render(json => {
		status => $success,
		($success
			? (result => $returned)
			: (error => $error)
		),
	});
}

sub sign ($self, $c, $body)
{
	my $signer = Signer::Transaction->new(
		parent => $self,
		input => $body,
	);

	my $tx = $signer->get_tx();
	return to_format [hex => $tx->to_serialized]
}

sub pubs ($self, $c, $body)
{
	my $gen = Signer::General->new(
		parent => $self,
		input => $body,
	);

	return $gen->get_pubs;

}

