package Signer::ClientScripts;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Mojo::File qw(path);
use Mojo::DOM;

has param 'directory' => (
	default => 'transactions',
);

has field 'local_state' => (
	writer => -hidden,
);

has field 'head' => (
	writer => -hidden,
);

sub _parse ($self, $file)
{
	my $dom = Mojo::DOM->new(path($file)->slurp);
	my $root = $dom->at('transaction');

	my $fee = $root->at('fee_rate')->text;
	my $skip = $root->at('skip_addresses');
	if (defined $skip) {
		$skip = $skip->text;
	}
	else {
		$skip = 0;
	}

	my $raw_inputs = $root->at('inputs')->children('input')->to_array;
	my @inputs;
	foreach my $input ($raw_inputs->@*) {
		push @inputs, {
			utxo => [$input->text, $input->attr('index')],
		};
	}

	my $raw_outputs = $root->at('outputs')->children('output')->to_array;
	my @outputs;
	foreach my $output ($raw_outputs->@*) {
		push @outputs, {
			value => $output->attr('value'),
			address => $output->text,
			check => exists $output->attr->{check},
		};
	}

	return {
		fee_rate => $fee,
		skip => $skip,
		inputs => \@inputs,
		outputs => \@outputs,
	};
}

sub _partial_parse ($self, $file, $state)
{
	my $data = $self->_parse($file);
	$state->{address} += $data->{skip};

	foreach my $output ($data->{outputs}->@*) {
		if ($output->{address} eq 'new_address') {
			$state->{address}++;
		}
		if ($output->{address} eq 'new_change') {
			$state->{change}++;
		}
	}

	return;
}

sub _full_parse ($self, $file, $state)
{
	my $data = $self->_parse($file);

	$state->{address} += $data->{skip};
	return {
		state => $state,
		tx => $data,
	};
}

sub BUILD ($self, $args)
{
	my @files = sort { $a cmp $b } glob $self->directory . '/*.xml';
	my $state = {
		change => 0,
		address => 0,
	};

	my $last = pop @files;
	foreach my $file (@files) {
		$self->_partial_parse($file, $state);
	}

	$self->_set_head($self->_full_parse($last, $state)) if $last;
	$self->_set_local_state($state);
}

