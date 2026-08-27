#!/usr/bin/env node
import { nodePorts } from "./node-ports.js";
import { serveLcpStdio } from "./stdio.js";

serveLcpStdio(nodePorts(process.env));
