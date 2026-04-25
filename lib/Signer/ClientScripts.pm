package Signer::ClientScripts;

use v5.40;
use Mooish::Base;
use Mojo::File qw(path);
use Mojo::DOM;
use Signer::ClientScripts::IndexTracker;

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

	# segwit is used by default for backcompat
	# (avoid changing transaction history in xml files)

	my $fee = $root->at('fee_rate');
	$fee = $fee->text if defined $fee;

	my %skip = (
		skip_addresses => {},
		skip_change => {},
	);

	foreach my $skip_type (qw(skip_addresses skip_change)) {
		my $raw_skip = $root->children($skip_type)->to_array;

		foreach my $to_skip ($raw_skip->@*) {
			my $type = $to_skip->attr->{type} // 'segwit';
			$skip{$skip_type}{$type} += $to_skip->text;
		}

		$skip{$skip_type} = Signer::ClientScripts::IndexTracker->new($skip{$skip_type});
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
			type => $output->attr->{type} // 'segwit',
		};
	}

	my $raw_meta = $root->at('meta');
	my %meta;
	if (defined $raw_meta) {
		$raw_meta = $raw_meta->children('prop')->to_array;
		foreach my $prop ($raw_meta->@*) {
			$meta{$prop->attr('name')} = $prop->text;
		}
	}

	return {
		fee_rate => $fee,
		inputs => \@inputs,
		outputs => \@outputs,
		meta => \%meta,
		%skip,
	};
}

sub _partial_parse ($self, $file, $state)
{
	my $data = $self->_parse($file);

	$state->{address} = $state->{address}->merge($data->{skip_addresses});
	$state->{change} = $state->{change}->merge($data->{skip_change});
	$state->{meta} = {
		($state->{meta} // {})->%*,
		$data->{meta}->%*,
	};

	foreach my $output ($data->{outputs}->@*) {
		if (fc $output->{address} eq fc 'new_address') {
			$state->{address}->increment($output->{type});
		}
		if (fc $output->{address} eq fc 'new_change') {
			$state->{change}->increment($output->{type});
		}
	}

	return;
}

sub _full_parse ($self, $file, $state)
{
	my $data = $self->_parse($file);

	$state->{address} = $state->{address}->merge($data->{skip_addresses});
	$state->{change} = $state->{change}->merge($data->{skip_change});

	$state->{meta} = {
		($state->{meta} // {})->%*,
		$data->{meta}->%*,
	};

	return {
		state => $state,
		tx => $data,
	};
}

sub BUILD ($self, $args)
{
	my @files = sort { $a cmp $b } glob $self->directory . '/*.xml';
	my $state = {
		change => Signer::ClientScripts::IndexTracker->new,
		address => Signer::ClientScripts::IndexTracker->new,
	};

	my $last = pop @files;
	foreach my $file (@files) {
		$self->_partial_parse($file, $state);
	}

	$self->_set_head($self->_full_parse($last, $state)) if $last;
	$self->_set_local_state($state);
}

