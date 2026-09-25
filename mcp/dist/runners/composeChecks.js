/**
 * Docker Compose hardening checks — `/guardian-docker` promised these
 * (privileged containers, host networking, a mounted `docker.sock`, `:latest`
 * image tags) and `scan_containers` never checked any of them: it only ran
 * Trivy against a Dockerfile and/or an image, never a compose file at all.
 *
 * Pure text -> Finding[]: no scanner, no filesystem beyond what the caller
 * already read. `scanContainers.ts` wraps this as a `ScannerParser` so it
 * flows through the same `parser_inputs` pipeline as every other finding.
 */
import { parse as parseYaml } from 'yaml';
import { makeFinding } from './scannerParsers/index.js';
export const COMPOSE_TOOL_NAME = 'docker-compose';
const CATEGORY = 'security';
export function checkCompose(text, filePath) {
    let doc;
    try {
        doc = parseYaml(text);
    }
    catch {
        return [];
    }
    const services = getServices(doc);
    if (services === null)
        return [];
    const findings = [];
    for (const [name, service] of services) {
        findings.push(...checkService(name, service, filePath));
    }
    return findings;
}
function checkService(name, service, filePath) {
    if (!isRecord(service))
        return [];
    const findings = [];
    if (service['privileged'] === true) {
        findings.push(finding({
            ruleId: 'compose-privileged',
            severity: 'critical',
            title: `Service "${name}" runs privileged`,
            message: `"${name}" sets privileged: true, which gives the container the same access to the host ` +
                'as a process running as root outside any container (all devices, all capabilities). Drop ' +
                'it and grant only the specific capabilities the container needs with cap_add instead.',
            filePath,
        }));
    }
    if (service['network_mode'] === 'host') {
        findings.push(finding({
            ruleId: 'compose-host-network',
            severity: 'high',
            title: `Service "${name}" uses host networking`,
            message: `"${name}" sets network_mode: host, which removes the network namespace isolation between ` +
                'the container and the host — the container can bind any host port and see the host\'s own ' +
                'network interfaces. Use the default bridge network and publish only the ports that are ' +
                'actually needed.',
            filePath,
        }));
    }
    if (mountsDockerSock(service['volumes'])) {
        findings.push(finding({
            ruleId: 'compose-docker-sock',
            severity: 'critical',
            title: `Service "${name}" mounts the Docker socket`,
            message: `"${name}" mounts /var/run/docker.sock into the container. Anything with access to that ` +
                'socket can start a new, privileged container and use it to read or write anything on the ' +
                'host — it is root-equivalent host access, not merely container access. Use a proxy that ' +
                'exposes only the specific Docker API calls the container needs, if any are needed at all.',
            filePath,
        }));
    }
    const image = service['image'];
    if (typeof image === 'string' && isUnpinnedTag(image)) {
        findings.push(finding({
            ruleId: 'compose-latest-tag',
            severity: 'medium',
            title: `Service "${name}" does not pin its image tag`,
            message: `"${name}" uses image "${image}", which resolves to :latest (explicitly or by omission). ` +
                'A rebuild pulls whatever the tag currently points to — not reproducible, and a compromised ' +
                'push to that tag reaches every deployment silently. Pin to a specific version tag or, ' +
                'stronger, a digest (image@sha256:...).',
            filePath,
        }));
    }
    return findings;
}
/** `services:` as `[name, definition][]`, or null when the document has none. */
function getServices(doc) {
    if (!isRecord(doc))
        return null;
    const services = doc['services'];
    if (!isRecord(services))
        return null;
    return Object.entries(services);
}
/**
 * Whether `volumes` (compose's short `"host:container[:mode]"` strings, or
 * the long `{type, source, target}` object form) mounts the Docker socket —
 * checked against either side, since the socket can be exposed at a
 * different path inside the container.
 */
function mountsDockerSock(volumes) {
    if (!Array.isArray(volumes))
        return false;
    return volumes.some((v) => {
        if (typeof v === 'string')
            return v.split(':').some((part) => part.trim() === '/var/run/docker.sock');
        if (isRecord(v)) {
            return v['source'] === '/var/run/docker.sock' || v['target'] === '/var/run/docker.sock';
        }
        return false;
    });
}
/**
 * Whether `image` resolves to `:latest` — explicitly, or by omission (no tag
 * at all). A digest reference (`image@sha256:...`) is the most reproducible
 * form there is and is never flagged, even with no tag. A registry host's
 * own port (`registry:5000/...`) must not be mistaken for a tag: only the
 * segment AFTER the last `/` is checked for a `:`.
 */
function isUnpinnedTag(image) {
    if (image.includes('@sha256:'))
        return false;
    const lastSegment = image.split('/').at(-1) ?? image;
    const colon = lastSegment.lastIndexOf(':');
    if (colon === -1)
        return true; // no tag at all -> implicit :latest
    return lastSegment.slice(colon + 1) === 'latest';
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function finding(opts) {
    return makeFinding({
        tool: COMPOSE_TOOL_NAME,
        rule_id: opts.ruleId,
        severity: opts.severity,
        category: CATEGORY,
        subcategory: 'compose',
        title: opts.title,
        message: opts.message,
        file_path: opts.filePath,
        fix_available: false,
    });
}
//# sourceMappingURL=composeChecks.js.map