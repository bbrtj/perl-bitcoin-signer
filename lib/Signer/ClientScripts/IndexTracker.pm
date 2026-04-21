package Signer::ClientScripts::IndexTracker;

use v5.40;
use Mooish::Base;

use constant AVAILABLE_TYPES => [
	'segwit',
	'taproot',
];

foreach my $type (AVAILABLE_TYPES->@*) {
	has param $type => (
		isa => PositiveOrZeroInt,
		writer => -hidden,
		default => 0,
	);
}

# strict construction
sub BUILD ($self, $args)
{
	my %keys = map { $_ => 1 } keys $args->%*;
	delete $keys{$_} foreach AVAILABLE_TYPES->@*;

	die 'Invalid address types: ' . join(', ', sort keys %keys)
		if %keys;
}

sub increment ($self, $type)
{
	my $action = "_set_$type";
	my $value = $self->$type;
	$self->$action($value + 1);

	return $value;
}

sub merge ($self, $other)
{
	return $self->new(
		segwit => $self->segwit + $other->segwit,
		taproot => $self->taproot + $other->taproot,
	);
}

