#!/bin/bash
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This test will run a number of parallel containers, and then try to
# 'rm -f' them all at the same time. It will check after each run and
# rm that we have the expected number of containers, shims, proxys,
# qemus and runtimes active
# The goals are two fold:
# - spot any stuck or non-started components
# - catch any hang ups

script_name=${0##*/}

# How many times will we run the test loop...
ITERATIONS=5

# the system 'free available' level where we stop running the tests, as otherwise
#  the system can crawl to a halt, and/or start refusing to launch new VMs anyway
# We choose 2G, as that is one of the default VM sizes for CC
MEM_CUTOFF=(2*1024*1024*1024)

# The default container/workload we run for testing
# nginx has show up issues in the past, for whatever reason, so
# let's default to that
PAYLOAD="nginx"

# do we need a command argument for this payload?
COMMAND=""

# Set the runtime if not set already
RUNTIME="${RUNTIME:-cc-runtime}"

# And set the names of the processes we look for
QEMU_NAME="${QEMU_NAME:-qemu-lite-system-x86_64}"
RUNTIME_NAME="${RUNTIME_NAME:-cc-runtime}"
SHIM_NAME="${SHIM_NAME:-cc-shim}"
PROXY_NAME="${PROXY_NAME:-cc-proxy}"

# The place where virtcontainers keeps its active pod info
# This is, I believe, ultimately what 'cc-runtime list' uses to get its info, but
# we can also check it for sanity directly
VC_POD_DIR="${VC_POD_DIR:-/var/lib/virtcontainers/pods}"

# let's cap the test. If you want to run until you hit the memory limit
# then just set this to a very large number
MAX_CONTAINERS=110

containerd="docker-containerd"
ctr="docker-containerd-ctr"

MANAGER="${MANAGER:-${docker}}"

function die() {
	msg="$*"
	echo >&2 "ERROR: $msg"
	exit 1
}

function docker_run() {
	local runtime="$1"
	local payload="$2"
	local command="$3"

	docker run --runtime=${runtime} -tid ${payload} ${command}
}

function containerd_run() {
	local runtime="$1"
	local payload="$2"
	local command="$3"

	local id=$(uuidgen)

	# copy the bundle dir for this container
	bundle_dir="/tmp/${id}-bundle-dir"
	sudo cp -a "$containerd_bundle_dir" "$bundle_dir"

	# FIXME: runtime path, redirect, background.
	sudo "$ctr" containers start \
		--runtime "$runtime" \
		"$id" \
		"$bundle_dir" &
}

function manager_run() {
	func="${MANAGER}_run"
	run_func "$func" $@
}

function docker_get_containers() {
	docker ps -qa
}

function docker_count_containers() {
	docker_get_containers | wc -l
}

function containerd_get_containers() {
	# FIXME: uncomment once the runtime supports "ps"!!
	#sudo "$ctr" containers list
	sudo cc-runtime list | awk '{print $1}'| tail -n +2
}

function containerd_count_containers() {
	containerd_get_containers | wc -l
}

function manager_count_containers() {
	func="${MANAGER}_count_containers"
	run_func "$func" $@
}

function check_all_running() {
	local goterror=0

	echo "Checking ${how_many} containers have all relevant components"

	# check what the container manager thinks
	how_many_running=$(manager_count_containers)

	if (( ${how_many_running} != ${how_many} )); then
		echo "Wrong number of containers running (${how_many_running} != ${how_many}) - stopping"
		((goterror++))
	fi

	# Only check for CC components if we are using a CC runtime
	if (( $check_cc_components )); then
		# check we have the right number of proxy's
		how_many_proxys=$(ps --no-header -C ${PROXY_NAME} | wc -l)
		if (( ${how_many_running} >= 1 )); then
			# If we have any containers, then we expect to have a single proxy
			if (( ${how_many_proxys} != 1 )); then
				echo "Wrong number of proxys running (${how_many_running} containers, ${how_many_proxys} proxys) - stopping"
				((goterror++))
			fi
		else
			# No containers running, but if we have run before then the proxy may still be running
			# It is not clear if the proxy quits if there are no containers left
			if (( ${how_many_proxys} > 1 )); then
				echo "Wrong number of proxys running (${how_many_running} containers, ${how_many_proxys} proxys) - stopping"
				((goterror++))
			fi
		fi

		# check we have the right number of shims
		how_many_shims=$(ps --no-header -C ${SHIM_NAME} | wc -l)
		# two shim processes per container...
		if (( ${how_many_running}*2 != ${how_many_shims} )); then
			echo "Wrong number of shims running (${how_many_running}*2 != ${how_many_shims}) - stopping"
			((goterror++))
		fi

		# check we have the right number of qemu's
		how_many_qemus=$(ps --no-header -C ${QEMU_NAME} | wc -l)
		if (( ${how_many_running} != ${how_many_qemus} )); then
			echo "Wrong number of qemus running (${how_many_running} != ${how_many_qemus}) - stopping"
			((goterror++))
		fi

		# check we have no runtimes running (they should be transient, we should not 'see them')
		how_many_runtimes=$(ps --no-header -C ${RUNTIME_NAME} | wc -l)
		if (( ${how_many_runtimes} )); then
			echo "Wrong number of runtimes running (${how_many_runtimes}) - stopping"
			((goterror++))
		fi

		# check how many containers the runtime list thinks we have
		num_list=$(sudo $RUNTIME list -q | wc -l)
		if (( ${how_many_running} != ${num_list} )); then
			echo "Wrong number of 'runtime list' containers running (${how_many_running} != ${num_list}) - stopping"
			((goterror++))
		fi

		# if this is cc-runtime, check how many pods virtcontainers thinks we have
		if [[ "$RUNTIME" == "cc-runtime" ]]; then
			num_vc_pods=$(sudo ls -1 ${VC_POD_DIR} | wc -l)

			if (( ${how_many_running} != ${num_vc_pods} )); then
				echo "Wrong number of pods in $VC_POD_DIR (${how_many_running} != ${num_vc_pods}) - stopping)"
				((goterror++))
			fi
		fi
	fi

	if (( goterror != 0 )); then
		echo "Got $goterror errors, quitting"
		exit -1
	fi
}

# reported system 'available' memory
function get_system_avail() {
	echo $(free -b | head -2 | tail -1 | awk '{print $7}')
}

function go() {
	echo "Running..."

	how_many=0

	while true; do {
		check_all_running

		echo "Run $RUNTIME: $PAYLOAD: $COMMAND"
		manager_run "${RUNTIME}" "${PAYLOAD}" "${COMMAND}"

		((how_many++))
		if (( ${how_many} > ${MAX_CONTAINERS} )); then
			echo "And we have hit the max ${how_many} containers"
			return
		fi

		how_much=$(get_system_avail)
		if (( ${how_much} < ${MEM_CUTOFF} )); then
			echo "And we are out of memory on container ${how_many} (${how_much} < ${MEM_CUTOFF})"
			return
		fi
	}
	done
}

function docker_kill_all_containers() {
	for container in $(docker_get_containers)
	do
		docker rm -f "$container"
	done
}

function containerd_kill_all_containers() {
	for container in $(containerd_get_containers)
	do
		sudo "$ctr" containers kill "$container"
	done
}

function manager_kill_all_containers() {
	func="${MANAGER}_kill_all_containers"
	run_func "$func"
}

function check_function() {
	local name="$1"

	type -t "$name" &>/dev/null || die "function '$name' does not exist"
}

function run_func() {
	name="$1"
	shift

	check_function "$name" && eval "$name" $@
}

function count_mounts() {
	echo $(mount | wc -l)
}

function check_mounts() {
	final_mount_count=$(count_mounts)

	if [[ $final_mount_count != $initial_mount_count ]]; then
		echo "Final mount count does not match initial count (${final_mount_count} != ${initial_mount_count})"
	fi
}

function manager_setup() {
	case "$MANAGER" in
		docker) ;;
		containerd)
			command -v containerd && containerd="containerd"
			command -v ctr && ctr="ctr"
			;;


		*)
			die "unsupported container manager: $MANAGER"
			;;
	esac

	#if [ "$manager" = docker ]; then
	#	sudo systemctl restart docker 
	#else
	#	sudo systemctl stop docker 
	#fi

	if [ "$MANAGER" = containerd ]; then
		command -v docker-containerd-shim || \
			sudo ln -s /usr/bin/docker-containerd-shim /usr/local/bin/containerd-shim

		# FIXME
		command -v runc || \
			sudo ln -s /usr/bin/docker-runc /usr/local/bin/runc

		# create payload from the docker image
		containerd_bundle_dir=$(mktemp -d /tmp/${script_name}.XXXXXXXXXX)
		containerd_rootfs_dir="$containerd_bundle_dir/rootfs"
		mkdir -p "$containerd_rootfs_dir"

		docker export $(docker create "$PAYLOAD") |\
			tar -C ${containerd_rootfs_dir} -xvf -

		# FIXME: what is changing config.json?
		#cd "$containerd_bundle_dir" && runc spec  && sudo chmod 444 config.json)
		(cd "$containerd_bundle_dir" && docker-runc spec)

		# FIXME: not deleted atm
		echo "DEBUG: containerd bundle directory: $containerd_bundle_dir"

		sudo "$containerd" --debug &

		# wait for the daemon to start up
		while [ 1 ]
		do
			echo "waiting for $containerd daemon"
			sudo docker-containerd-ctr version && break
		done
	else
		sudo killall -9 "$containerd"
	fi
}

function init() {
	manager_setup
	manager_kill_all_containers

	# remember how many mount points we had before we do anything
	# and then sanity check we end up with no new ones dangling at the end
	initial_mount_count=$(count_mounts)

	# Only check CC items if we are using a CC runtime
	if [[ "$RUNTIME" == "cor" ]] || [[ "$RUNTIME" == "cc-runtime" ]]; then
		echo "Checking CC runtime $RUNTIME"
		check_cc_components=1
	else
		echo "Not a CC runtime, not checking for CC components"
		check_cc_components=0
	fi
}

function spin() {
	for ((i=1; i<= ITERATIONS; i++)); do {
		echo "Start loop $i"
		#spin them up
		go
		#check we are in a sane state
		check_all_running
		#shut them all down
		manager_kill_all_containers
		#Note there should be none running
		how_many=0
		#and check they all died
		check_all_running
		#and that we have no dangling mounts
		check_mounts
	}
	done
}

init
spin
