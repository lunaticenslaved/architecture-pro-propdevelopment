#!/usr/bin/env bash

minikube stop
minikube delete --all

rm -rf $HOME/.minikube

mkdir -p $HOME/.minikube/files/etc/ssl/certs
cp ./audit-policy.yaml $HOME/.minikube/files/etc/ssl/certs/

minikube start \
    --vm-driver=docker \
    --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml \
    --extra-config=apiserver.audit-log-path=-

minikube kubectl -- get pods -A
