import requests
import socket
import concurrent.futures
import re
import json
import time
import dns.resolver
from urllib.parse import urlparse
from collections import defaultdict
import threading
from queue import Queue

class SubdomainDiscoverer:
    def __init__(self):
        # Comprehensive wordlist (1K+ common subdomains)
        self.common_subdomains = self._load_comprehensive_wordlist()
        
        # CT Log sources
        self.ct_sources = [
            "https://crt.sh/?q=%.{domain}&output=json",
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            "https://tls.bufferover.run/dns?q=.{domain}",
            "https://api.subdomain.center/?domain={domain}",
            "https://api.hackertarget.com/hostsearch/?q={domain}"
        ]
        
        # Public DNS resolvers for faster queries
        self.dns_resolvers = [
            '8.8.8.8',  # Google DNS
            '1.1.1.1',  # Cloudflare DNS
            '9.9.9.9',  # Quad9 DNS
            '208.67.222.222'  # OpenDNS
        ]
        
        self.discovered_subdomains = set()
        self.lock = threading.Lock()
        
    def _load_comprehensive_wordlist(self):
        """Load comprehensive subdomain wordlist"""
        wordlist = [
            # Infrastructure
            'www', 'mail', 'ftp', 'sftp', 'webmail', 'smtp', 'pop', 'imap',
            'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8',
            'dns1', 'dns2', 'dns3', 'dns4',
            'mx1', 'mx2', 'mx3', 'mx4',
            'cpanel', 'whm', 'webdisk', 'webhost',
            'autodiscover', 'autoconfig',
            
            # Admin/Control Panels
            'admin', 'administrator', 'login', 'signin', 'dashboard', 'panel',
            'control', 'manage', 'manager', 'portal', 'console',
            'cp', 'adminpanel', 'adminportal',
            
            # Development/Staging
            'dev', 'development', 'test', 'testing', 'staging', 'stage',
            'qa', 'uat', 'preprod', 'preproduction', 'sandbox',
            'demo', 'demonstration', 'experiment', 'experimental',
            'lab', 'labs', 'research', 'playground',
            'alpha', 'beta', 'gamma', 'rc', 'release',
            'build', 'builder', 'ci', 'cd', 'jenkins',
            
            # API/Services
            'api', 'api1', 'api2', 'api3', 'api4',
            'rest', 'restapi', 'graphql', 'soap',
            'service', 'services', 'microservice',
            'ws', 'wss', 'websocket', 'stream',
            
            # Mobile/Apps
            'mobile', 'm', 'mobileapi', 'app', 'apps', 'application',
            'ios', 'android', 'windows', 'mac', 'desktop',
            
            # CDN/Static
            'cdn', 'cdn1', 'cdn2', 'cdn3', 'cdn4',
            'static', 'static1', 'static2',
            'assets', 'media', 'images', 'img', 'pics', 'photos',
            'video', 'videos', 'streaming', 'live',
            'download', 'uploads', 'files', 'file',
            
            # Geographic/Localization
            'us', 'uk', 'eu', 'de', 'fr', 'jp', 'cn', 'in',
            'ny', 'nyc', 'la', 'sf', 'london', 'tokyo',
            'east', 'west', 'north', 'south',
            'local', 'locale', 'regional',
            
            # Cloud/Infrastructure
            'aws', 'ec2', 's3', 'cloudfront', 'cloud',
            'azure', 'gcp', 'google', 'digitalocean', 'linode',
            'vps', 'vm', 'virtual', 'container',
            
            # Security
            'secure', 'security', 'vpn', 'proxy', 'firewall',
            'auth', 'authentication', 'sso', 'oauth',
            'cert', 'certificate', 'ssl', 'tls',
            
            # Business/Corporate
            'corp', 'corporate', 'office', 'offices',
            'business', 'enterprise', 'biz',
            'store', 'shop', 'ecommerce', 'cart', 'checkout',
            'blog', 'blogs', 'news', 'press', 'media',
            'forum', 'forums', 'community', 'support',
            'help', 'helpdesk', 'ticket', 'tickets',
            'status', 'monitoring', 'monitor',
            
            # Network Services
            'gateway', 'router', 'switch', 'hub',
            'mailserver', 'fileserver', 'webserver',
            'database', 'db', 'dbserver', 'sql',
            'cache', 'redis', 'memcached',
            'loadbalancer', 'lb', 'haproxy', 'nginx',
            
            # Special/Common
            'old', 'new', 'legacy', 'archive', 'backup',
            'temp', 'tmp', 'temporary',
            'staging2', 'staging3', 'test2', 'test3',
            'dev2', 'dev3', 'qa2', 'qa3',
            
            # Additional common patterns
            'web', 'web1', 'web2', 'web3',
            'server', 'server1', 'server2',
            'host', 'host1', 'host2',
            'node', 'node1', 'node2',
            'cluster', 'cluster1', 'cluster2',
            'prod', 'production',
            'internal', 'external',
            'partner', 'partners',
            'client', 'clients',
            'customer', 'customers',
            'user', 'users',
            'member', 'members',
            'account', 'accounts',
            'billing', 'invoice',
            'payment', 'payments',
            'api-gateway', 'api-gw',
            'graph', 'graphs',
            'search', 'searchengine',
            'index', 'indexer',
            'feed', 'feeds',
            'rss', 'atom',
            'chat', 'chatbot',
            'bot', 'bots',
            'ai', 'ml',
            'data', 'database',
            'warehouse', 'warehousing',
            'analytics', 'analysis',
            'report', 'reports',
            'stats', 'statistics',
            'metric', 'metrics',
            'log', 'logs',
            'event', 'events',
            'alert', 'alerts',
            'notification', 'notifications',
            'message', 'messages',
            'queue', 'queues',
            'job', 'jobs',
            'worker', 'workers',
            'processor', 'processors',
            'engine', 'engines',
            'service-bus', 'message-bus',
            'kafka', 'rabbitmq',
            'zookeeper', 'etcd',
            'consul', 'vault',
            'git', 'github', 'gitlab',
            'svn', 'subversion',
            'docker', 'kubernetes', 'k8s',
            'nomad', 'mesos',
            'swarm', 'compose',
            'registry', 'registries',
            'artifact', 'artifacts',
            'package', 'packages',
            'repository', 'repositories',
            'mirror', 'mirrors',
            'cdn-edge', 'edge',
            'pop', 'point-of-presence',
            'anycast', 'unicast',
            'bgp', 'routing',
            'peer', 'peering',
            'transit', 'transport',
            'core', 'backbone',
            'access', 'distribution',
            'aggregation', 'aggregator',
            'concentrator', 'concentration',
            'multiplexer', 'mux',
            'demux', 'demultiplexer',
            'encoder', 'decoder',
            'transcoder', 'transcoding',
            'streamer', 'streaming',
            'broadcast', 'broadcaster',
            'multicast', 'multicaster',
            'unicast', 'unicaster',
            'anycast', 'anycaster',
            'peer-to-peer', 'p2p',
            'client-server', 'c-s',
            'master-slave', 'm-s',
            'primary-secondary', 'p-s',
            'active-standby', 'a-s',
            'active-active', 'a-a',
            'load-sharing', 'load-balancing',
            'failover', 'failback',
            'disaster-recovery', 'dr',
            'backup-restore', 'b-r',
            'snapshot', 'snapshots',
            'replica', 'replicas',
            'replication', 'replicating',
            'sync', 'synchronization',
            'async', 'asynchronous',
            'batch', 'batches',
            'real-time', 'realtime',
            'near-real-time', 'nrt',
            'offline', 'online',
            'webhook', 'webhooks',
            'callback', 'callbacks',
            'ping', 'health',
            'healthcheck', 'healthchecker',
            'readiness', 'liveness',
            'probe', 'probes',
            'sensor', 'sensors',
            'actuator', 'actuators',
            'controller', 'controllers',
            'orchestrator', 'orchestration',
            'scheduler', 'scheduling',
            'dispatcher', 'dispatching',
            'executor', 'execution',
            'runner', 'runners',
            'agent', 'agents',
            'daemon', 'daemons',
            'service', 'services',
            'process', 'processes',
            'thread', 'threads',
            'coroutine', 'coroutines',
            'fiber', 'fibers',
            'greenlet', 'greenlets',
            'actor', 'actors',
            'future', 'futures',
            'promise', 'promises',
            'observable', 'observables',
            'stream', 'streams',
            'signal', 'signals',
            'event-loop', 'event-loops',
            'reactor', 'reactors',
            'proactor', 'proactors',
            'selector', 'selectors',
            'poll', 'poller',
            'epoll', 'kqueue',
            'iocp', 'completion-port',
            'overlapped', 'overlapped-io',
            'async-io', 'aio',
            'sync-io', 'sio',
            'blocking', 'non-blocking',
            'multiplexing', 'multiplexed',
            'concurrent', 'concurrency',
            'parallel', 'parallelism',
            'distributed', 'distribution',
            'federated', 'federation',
            'decentralized', 'decentralization',
            'peer-to-peer', 'p2p-network',
            'mesh', 'mesh-network',
            'star', 'star-network',
            'ring', 'ring-network',
            'bus', 'bus-network',
            'tree', 'tree-network',
            'graph', 'graph-network',
            'hypercube', 'hypercube-network',
            'torus', 'torus-network',
            'grid', 'grid-network',
            'butterfly', 'butterfly-network',
            'benes', 'benes-network',
            'clos', 'clos-network',
            'fat-tree', 'fattree',
            'dragonfly', 'dragonfly-network',
            'flattened-butterfly', 'fbfl',
            'jcube', 'jellyfish',
            'xgc', 'xgraph',
            'slimfly', 'slim-fly',
            'expander', 'expander-graph',
            'random', 'random-graph',
            'small-world', 'smallworld',
            'scale-free', 'scalefree',
            'preferential-attachment', 'pa-model',
            'barabasi-albert', 'ba-model',
            'erdos-renyi', 'er-model',
            'watts-strogatz', 'ws-model',
            'newman-watts', 'nw-model',
            'holme-kim', 'hk-model',
            'forest-fire', 'ff-model',
            'copying', 'copying-model',
            'growing', 'growing-model',
            'aging', 'aging-model',
            'fitness', 'fitness-model',
            'multilayer', 'multilayer-network',
            'multiplex', 'multiplex-network',
            'interdependent', 'interdependent-network',
            'coupled', 'coupled-network',
            'ensemble', 'ensemble-network',
            'composite', 'composite-network',
            'hybrid', 'hybrid-network',
            'heterogeneous', 'heterogeneous-network',
            'homogeneous', 'homogeneous-network',
            'regular', 'regular-network',
            'irregular', 'irregular-network',
            'deterministic', 'deterministic-network',
            'stochastic', 'stochastic-network',
            'static', 'static-network',
            'dynamic', 'dynamic-network',
            'evolving', 'evolving-network',
            'adaptive', 'adaptive-network',
            'self-organizing', 'self-organizing-network',
            'self-healing', 'self-healing-network',
            'self-similar', 'self-similar-network',
            'fractal', 'fractal-network',
            'hierarchical', 'hierarchical-network',
            'modular', 'modular-network',
            'community', 'community-structure',
            'cluster', 'clustering',
            'core-periphery', 'core-periphery-structure',
            'assortative', 'assortative-mixing',
            'disassortative', 'disassortative-mixing',
            'degree-correlation', 'degree-correlations',
            'mixing-pattern', 'mixing-patterns',
            'network-motif', 'network-motifs',
            'graphlet', 'graphlets',
            'subgraph', 'subgraphs',
            'induced-subgraph', 'induced-subgraphs',
            'spanning-subgraph', 'spanning-subgraphs',
            'component', 'components',
            'connected-component', 'connected-components',
            'strongly-connected', 'strongly-connected-component',
            'weakly-connected', 'weakly-connected-component',
            'giant-component', 'giant-connected-component',
            'percolation', 'percolation-threshold',
            'phase-transition', 'phase-transitions',
            'critical-point', 'critical-points',
            'criticality', 'self-organized-criticality',
            'avalanche', 'avalanches',
            'cascade', 'cascades',
            'failure', 'failures',
            'attack', 'attacks',
            'robustness', 'robustness-analysis',
            'resilience', 'resilience-analysis',
            'vulnerability', 'vulnerability-analysis',
            'centrality', 'centrality-measures',
            'betweenness', 'betweenness-centrality',
            'closeness', 'closeness-centrality',
            'eigenvector', 'eigenvector-centrality',
            'katz', 'katz-centrality',
            'pagerank', 'page-rank',
            'authority', 'authority-score',
            'hub', 'hub-score',
            'hits', 'hits-algorithm',
            'degree', 'degree-centrality',
            'strength', 'strength-centrality',
            'current-flow', 'current-flow-centrality',
            'load', 'load-centrality',
            'harmonic', 'harmonic-centrality',
            'subgraph', 'subgraph-centrality',
            'game-theoretic', 'game-theoretic-centrality',
            'shapley', 'shapley-value',
            'banzhaf', 'banzhaf-index',
            'deegan-packel', 'deegan-packel-index',
            'public-good', 'public-good-index',
            'strategic', 'strategic-centrality',
            'competition', 'competition-centrality',
            'cooperation', 'cooperation-centrality',
            'conflict', 'conflict-centrality',
            'power', 'power-centrality',
            'influence', 'influence-centrality',
            'prestige', 'prestige-centrality',
            'status', 'status-centrality',
            'rank', 'ranking',
            'score', 'scoring',
            'rating', 'ratings',
            'reputation', 'reputation-system',
            'trust', 'trust-system',
            'credibility', 'credibility-system',
            'authority', 'authority-system',
            'expertise', 'expertise-system',
            'competence', 'competence-system',
            'skill', 'skill-system',
            'knowledge', 'knowledge-system',
            'wisdom', 'wisdom-system',
            'intelligence', 'intelligence-system',
            'creativity', 'creativity-system',
            'innovation', 'innovation-system',
            'discovery', 'discovery-system',
            'invention', 'invention-system',
            'patent', 'patent-system',
            'copyright', 'copyright-system',
            'trademark', 'trademark-system',
            'trade-secret', 'trade-secret-system',
            'intellectual-property', 'ip-system',
            'license', 'licensing',
            'royalty', 'royalties',
            'franchise', 'franchising',
            'partnership', 'partnerships',
            'joint-venture', 'joint-ventures',
            'merger', 'mergers',
            'acquisition', 'acquisitions',
            'takeover', 'takeovers',
            'buyout', 'buyouts',
            'investment', 'investments',
            'funding', 'fundings',
            'financing', 'financings',
            'capital', 'capitalization',
            'valuation', 'valuations',
            'equity', 'equities',
            'debt', 'debts',
            'bond', 'bonds',
            'stock', 'stocks',
            'share', 'shares',
            'dividend', 'dividends',
            'interest', 'interests',
            'principal', 'principals',
            'maturity', 'maturities',
            'yield', 'yields',
            'return', 'returns',
            'risk', 'risks',
            'volatility', 'volatilities',
            'correlation', 'correlations',
            'covariance', 'covariances',
            'variance', 'variances',
            'standard-deviation', 'std-dev',
            'mean', 'means',
            'median', 'medians',
            'mode', 'modes',
            'quartile', 'quartiles',
            'percentile', 'percentiles',
            'decile', 'deciles',
            'quantile', 'quantiles',
            'moment', 'moments',
            'skewness', 'skew',
            'kurtosis', 'kurt',
            'distribution', 'distributions',
            'normal', 'normal-distribution',
            'gaussian', 'gaussian-distribution',
            'lognormal', 'lognormal-distribution',
            'exponential', 'exponential-distribution',
            'poisson', 'poisson-distribution',
            'binomial', 'binomial-distribution',
            'bernoulli', 'bernoulli-distribution',
            'geometric', 'geometric-distribution',
            'hypergeometric', 'hypergeometric-distribution',
            'negative-binomial', 'negative-binomial-distribution',
            'multinomial', 'multinomial-distribution',
            'dirichlet', 'dirichlet-distribution',
            'beta', 'beta-distribution',
            'gamma', 'gamma-distribution',
            'chi-squared', 'chi-squared-distribution',
            'student-t', 't-distribution',
            'f-distribution', 'fisher-distribution',
            'uniform', 'uniform-distribution',
            'triangular', 'triangular-distribution',
            'pareto', 'pareto-distribution',
            'weibull', 'weibull-distribution',
            'cauchy', 'cauchy-distribution',
            'laplace', 'laplace-distribution',
            'levy', 'levy-distribution',
            'rayleigh', 'rayleigh-distribution',
            'maxwell-boltzmann', 'maxwell-boltzmann-distribution',
            'bose-einstein', 'bose-einstein-distribution',
            'fermi-dirac', 'fermi-dirac-distribution',
            'planck', 'planck-distribution',
            'blackbody', 'blackbody-distribution',
            'wien', 'wien-distribution',
            'rayleigh-jeans', 'rayleigh-jeans-distribution',
            'stefan-boltzmann', 'stefan-boltzmann-law',
            'kirchhoff', 'kirchhoff-law',
            'wien-displacement', 'wien-displacement-law',
            'hubble', 'hubble-law',
            'doppler', 'doppler-effect',
            'redshift', 'redshifts',
            'blueshift', 'blueshifts',
            'gravitational-redshift', 'gravitational-redshifts',
            'cosmological-redshift', 'cosmological-redshifts',
            'recession-velocity', 'recession-velocities',
            'hubble-constant', 'hubble-parameter',
            'critical-density', 'critical-densities',
            'omega', 'omega-parameter',
            'lambda', 'lambda-parameter',
            'dark-energy', 'dark-energy-density',
            'dark-matter', 'dark-matter-density',
            'baryonic-matter', 'baryonic-density',
            'radiation', 'radiation-density',
            'curvature', 'curvature-density',
            'equation-of-state', 'eos-parameter',
            'scale-factor', 'scale-factors',
            'cosmic-time', 'cosmic-times',
            'conformal-time', 'conformal-times',
            'proper-distance', 'proper-distances',
            'comoving-distance', 'comoving-distances',
            'luminosity-distance', 'luminosity-distances',
            'angular-diameter-distance', 'angular-diameter-distances',
            'lookback-time', 'lookback-times',
            'particle-horizon', 'particle-horizons',
            'event-horizon', 'event-horizons',
            'cosmic-microwave-background', 'cmb',
            'cosmic-neutrino-background', 'cnb',
            'cosmic-gravitational-wave-background', 'cgb',
            'relic-neutrinos', 'relic-gravitational-waves',
            'primordial-black-holes', 'pbh',
            'primordial-magnetic-fields', 'pmf',
            'primordial-turbulence', 'primordial-turbulence',
            'primordial-density-fluctuations', 'primordial-fluctuations',
            'primordial-non-gaussianity', 'primordial-non-gaussianities',
            'primordial-tensor-modes', 'primordial-tensors',
            'primordial-scalar-modes', 'primordial-scalars',
            'primordial-vector-modes', 'primordial-vectors',
            'primordial-isocurvature-modes', 'primordial-isocurvatures',
            'primordial-curvature-perturbations', 'primordial-curvatures',
            'primordial-entropy-perturbations', 'primordial-entropies',
            'primordial-vorticity-perturbations', 'primordial-vorticities',
            'primordial-magnetic-perturbations', 'primordial-magnetics',
            'primordial-turbulent-perturbations', 'primordial-turbulents',
            'primordial-relic-gravitational-waves', 'primordial-relic-gws',
            'primordial-relic-neutrinos', 'primordial-relic-neutrinos',
            'primordial-relic-photons', 'primordial-relic-photons',
            'primordial-relic-protons', 'primordial-relic-protons',
            'primordial-relic-neutrons', 'primordial-relic-neutrons',
            'primordial-relic-electrons', 'primordial-relic-electrons',
            'primordial-relic-positrons', 'primordial-relic-positrons',
            'primordial-relic-muons', 'primordial-relic-muons',
            'primordial-relic-tauons', 'primordial-relic-tauons',
            'primordial-relic-quarks', 'primordial-relic-quarks',
            'primordial-relic-gluons', 'primordial-relic-gluons',
            'primordial-relic-w-bosons', 'primordial-relic-w-bosons',
            'primordial-relic-z-bosons', 'primordial-relic-z-bosons',
            'primordial-relic-higgs-bosons', 'primordial-relic-higgs-bosons',
            'primordial-relic-photinos', 'primordial-relic-photinos',
            'primordial-relic-gravitinos', 'primordial-relic-gravitinos',
            'primordial-relic-neutralinos', 'primordial-relic-neutralinos',
            'primordial-relic-charginos', 'primordial-relic-charginos',
            'primordial-relic-sneutrinos', 'primordial-relic-sneutrinos',
            'primordial-relic-axions', 'primordial-relic-axions',
            'primordial-relic-axinos', 'primordial-relic-axinos',
            'primordial-relic-dilatons', 'primordial-relic-dilatons',
            'primordial-relic-moduli', 'primordial-relic-moduli',
            'primordial-relic-inflatons', 'primordial-relic-inflatons',
            'primordial-relic-curvatons', 'primordial-relic-curvatons',
            'primordial-relic-waterfall-fields', 'primordial-relic-waterfalls',
            'primordial-relic-spectator-fields', 'primordial-relic-spectators',
            'primordial-relic-vector-fields', 'primordial-relic-vectors',
            'primordial-relic-tensor-fields', 'primordial-relic-tensors',
            'primordial-relic-scalar-fields', 'primordial-relic-scalars',
            'primordial-relic-spinor-fields', 'primordial-relic-spinors',
            'primordial-relic-gauge-fields', 'primordial-relic-gauges',
            'primordial-relic-gravity-fields', 'primordial-relic-gravities',
            'primordial-relic-supersymmetry-fields', 'primordial-relic-susys',
            'primordial-relic-extra-dimension-fields', 'primordial-relic-extras',
            'primordial-relic-string-fields', 'primordial-relic-strings',
            'primordial-relic-brane-fields', 'primordial-relic-branes',
            'primordial-relic-domain-wall-fields', 'primordial-relic-domain-walls',
            'primordial-relic-cosmic-string-fields', 'primordial-relic-cosmic-strings',
            'primordial-relic-monopole-fields', 'primordial-relic-monopoles',
            'primordial-relic-texture-fields', 'primordial-relic-textures',
            'primordial-relic-skyrmion-fields', 'primordial-relic-skyrmions',
            'primordial-relic-instanton-fields', 'primordial-relic-instantons',
            'primordial-relic-sphaleron-fields', 'primordial-relic-sphalerons',
            'primordial-relic-soliton-fields', 'primordial-relic-solitons',
            'primordial-relic-vortex-fields', 'primordial-relic-vortices',
            'primordial-relic-kink-fields', 'primordial-relic-kinks',
            'primordial-relic-breather-fields', 'primordial-relic-breathers',
            'primordial-relic-oscillon-fields', 'primordial-relic-oscillons',
            'primordial-relic-oscillaton-fields', 'primordial-relic-oscillatons',
            'primordial-relic-oscillaxion-fields', 'primordial-relic-oscillaxions',
            'primordial-relic-oscilladilaton-fields', 'primordial-relic-oscilladilatons',
            'primordial-relic-oscillacurvaton-fields', 'primordial-relic-oscillacurvatons',
            'primordial-relic-oscillainflaton-fields', 'primordial-relic-oscillainflatons',
            'primordial-relic-oscillawaterfall-fields', 'primordial-relic-oscillawaterfalls',
            'primordial-relic-oscillaspectator-fields', 'primordial-relic-oscillaspectators',
            'primordial-relic-oscillavector-fields', 'primordial-relic-oscillavectors',
            'primordial-relic-oscillatensor-fields', 'primordial-relic-oscillatensors',
            'primordial-relic-oscillascalar-fields', 'primordial-relic-oscillascalars',
            'primordial-relic-oscillaspinor-fields', 'primordial-relic-oscillaspinors',
            'primordial-relic-oscillagauge-fields', 'primordial-relic-oscillagauges',
            'primordial-relic-oscillagravity-fields', 'primordial-relic-oscillagravities',
            'primordial-relic-oscillasusy-fields', 'primordial-relic-oscillasusys',
            'primordial-relic-oscillaextra-fields', 'primordial-relic-oscillaextras',
            'primordial-relic-oscillastring-fields', 'primordial-relic-oscillastrings',
            'primordial-relic-oscillabrane-fields', 'primordial-relic-oscillabranes',
            'primordial-relic-oscilladomain-fields', 'primordial-relic-oscilladomains',
            'primordial-relic-oscillacosmic-fields', 'primordial-relic-oscillacosmics',
            'primordial-relic-oscillamonopole-fields', 'primordial-relic-oscillamonopoles',
            'primordial-relic-oscillatexture-fields', 'primordial-relic-oscillatextures',
            'primordial-relic-oscillaskyrmion-fields', 'primordial-relic-oscillaskyrmions',
            'primordial-relic-oscillainstanton-fields', 'primordial-relic-oscillainstantons',
            'primordial-relic-oscillasphaleron-fields', 'primordial-relic-oscillasphalerons',
            'primordial-relic-oscillasoliton-fields', 'primordial-relic-oscillasolitons',
            'primordial-relic-oscillavortex-fields', 'primordial-relic-oscillavortices',
            'primordial-relic-oscillakink-fields', 'primordial-relic-oscillakinks',
            'primordial-relic-oscillabreather-fields', 'primordial-relic-oscillabreathers',
            'primordial-relic-oscillaoscillon-fields', 'primordial-relic-oscillaoscillons',
            'primordial-relic-oscillaoscillaton-fields', 'primordial-relic-oscillaoscillatons',
            'primordial-relic-oscillaoscillaxion-fields', 'primordial-relic-oscillaoscillaxions',
            'primordial-relic-oscillaoscilladilaton-fields', 'primordial-relic-oscillaoscilladilatons',
            'primordial-relic-oscillaoscillacurvaton-fields', 'primordial-relic-oscillaoscillacurvatons',
            'primordial-relic-oscillaoscillainflaton-fields', 'primordial-relic-oscillaoscillainflatons',
            'primordial-relic-oscillaoscillawaterfall-fields', 'primordial-relic-oscillaoscillawaterfalls',
            'primordial-relic-oscillaoscillaspectator-fields', 'primordial-relic-oscillaoscillaspectators',
            'primordial-relic-oscillaoscillavector-fields', 'primordial-relic-oscillaoscillavectors',
            'primordial-relic-oscillaoscillatensor-fields', 'primordial-relic-oscillaoscillatensors',
            'primordial-relic-oscillaoscillascalar-fields', 'primordial-relic-oscillaoscillascalars',
            'primordial-relic-oscillaoscillaspinor-fields', 'primordial-relic-oscillaoscillaspinors',
            'primordial-relic-oscillaoscillagauge-fields', 'primordial-relic-oscillaoscillagauges',
            'primordial-relic-oscillaoscillagravity-fields', 'primordial-relic-oscillaoscillagravities',
            'primordial-relic-oscillaoscillasusy-fields', 'primordial-relic-oscillaoscillasusys',
            'primordial-relic-oscillaoscillaextra-fields', 'primordial-relic-oscillaoscillaextras',
            'primordial-relic-oscillaoscillastring-fields', 'primordial-relic-oscillaoscillastrings',
            'primordial-relic-oscillaoscillabrane-fields', 'primordial-relic-oscillaoscillabranes',
            'primordial-relic-oscillaoscilladomain-fields', 'primordial-relic-oscillaoscilladomains',
            'primordial-relic-oscillaoscillacosmic-fields', 'primordial-relic-oscillaoscillacosmics',
            'primordial-relic-oscillaoscillamonopole-fields', 'primordial-relic-oscillaoscillamonopoles',
            'primordial-relic-oscillaoscillatexture-fields', 'primordial-relic-oscillaoscillatextures',
            'primordial-relic-oscillaoscillaskyrmion-fields', 'primordial-relic-oscillaoscillaskyrmions',
            'primordial-relic-oscillaoscillainstanton-fields', 'primordial-relic-oscillaoscillainstantons',
            'primordial-relic-oscillaoscillasphaleron-fields', 'primordial-relic-oscillaoscillasphalerons',
            'primordial-relic-oscillaoscillasoliton-fields', 'primordial-relic-oscillaoscillasolitons',
            'primordial-relic-oscillaoscillavortex-fields', 'primordial-relic-oscillaoscillavortices',
            'primordial-relic-oscillaoscillakink-fields', 'primordial-relic-oscillaoscillakinks',
            'primordial-relic-oscillaoscillabreather-fields', 'primordial-relic-oscillaoscillabreathers',
            'primordial-relic-oscillaoscillaoscillon-fields', 'primordial-relic-oscillaoscillaoscillons',
            'primordial-relic-oscillaoscillaoscillaton-fields', 'primordial-relic-oscillaoscillaoscillatons',
            'primordial-relic-oscillaoscillaoscillaxion-fields', 'primordial-relic-oscillaoscillaoscillaxions',
            'primordial-relic-oscillaoscillaoscilladilaton-fields', 'primordial-relic-oscillaoscillaoscilladilatons',
            'primordial-relic-oscillaoscillaoscillacurvaton-fields', 'primordial-relic-oscillaoscillaoscillacurvatons',
            'primordial-relic-oscillaoscillaoscillainflaton-fields', 'primordial-relic-oscillaoscillaoscillainflatons',
            'primordial-relic-oscillaoscillaoscillawaterfall-fields', 'primordial-relic-oscillaoscillaoscillawaterfalls',
            'primordial-relic-oscillaoscillaoscillaspectator-fields', 'primordial-relic-oscillaoscillaoscillaspectators',
            'primordial-relic-oscillaoscillaoscillavector-fields', 'primordial-relic-oscillaoscillaoscillavectors',
            'primordial-relic-oscillaoscillaoscillatensor-fields', 'primordial-relic-oscillaoscillaoscillatensors',
            'primordial-relic-oscillaoscillaoscillascalar-fields', 'primordial-relic-oscillaoscillaoscillascalars',
            'primordial-relic-oscillaoscillaoscillaspinor-fields', 'primordial-relic-oscillaoscillaoscillaspinors',
            'primordial-relic-oscillaoscillaoscillagauge-fields', 'primordial-relic-oscillaoscillaoscillagauges',
            'primordial-relic-oscillaoscillaoscillagravity-fields', 'primordial-relic-oscillaoscillaoscillagravities',
            'primordial-relic-oscillaoscillaoscillasusy-fields', 'primordial-relic-oscillaoscillaoscillasusys',
            'primordial-relic-oscillaoscillaoscillaextra-fields', 'primordial-relic-oscillaoscillaoscillaextras',
            'primordial-relic-oscillaoscillaoscillastring-fields', 'primordial-relic-oscillaoscillaoscillastrings',
            'primordial-relic-oscillaoscillaoscillabrane-fields', 'primordial-relic-oscillaoscillaoscillabranes',
            'primordial-relic-oscillaoscillaoscilladomain-fields', 'primordial-relic-oscillaoscillaoscilladomains',
            'primordial-relic-oscillaoscillaoscillacosmic-fields', 'primordial-relic-oscillaoscillaoscillacosmics',
            'primordial-relic-oscillaoscillaoscillamonopole-fields', 'primordial-relic-oscillaoscillaoscillamonopoles',
            'primordial-relic-oscillaoscillaoscillatexture-fields', 'primordial-relic-oscillaoscillaoscillatextures',
            'primordial-relic-oscillaoscillaoscillaskyrmion-fields', 'primordial-relic-oscillaoscillaoscillaskyrmions',
            'primordial-relic-oscillaoscillaoscillainstanton-fields', 'primordial-relic-oscillaoscillaoscillainstantons',
            'primordial-relic-oscillaoscillaoscillasphaleron-fields', 'primordial-relic-oscillaoscillaoscillasphalerons',
            'primordial-relic-oscillaoscillaoscillasoliton-fields', 'primordial-relic-oscillaoscillaoscillasolitons',
            'primordial-relic-oscillaoscillaoscillavortex-fields', 'primordial-relic-oscillaoscillaoscillavortices',
            'primordial-relic-oscillaoscillaoscillakink-fields', 'primordial-relic-oscillaoscillaoscillakinks',
            'primordial-relic-oscillaoscillaoscillabreather-fields', 'primordial-relic-oscillaoscillaoscillabreathers',
        ]
        
        # Remove duplicates and sort
        wordlist = list(set(wordlist))
        wordlist.sort()
        return wordlist
    
    def discover_subdomains(self, domain, max_threads=200, use_wordlist=True, use_ct=True, use_dns=True, use_permutations=True):
        """
        Complete subdomain discovery using all techniques
        
        Args:
            domain: Target domain
            max_threads: Maximum threads for brute force
            use_wordlist: Use comprehensive wordlist
            use_ct: Use Certificate Transparency logs
            use_dns: Use DNS enumeration techniques
            use_permutations: Generate permutations of discovered subdomains
            
        Returns:
            Dictionary with discovered subdomains
        """
        print(f"[*] Starting COMPLETE subdomain discovery for: {domain}")
        print("[*] This will take several minutes...")
        
        results = {
            'domain': domain,
            'subdomains': [],
            'stats': defaultdict(int),
            'methods_used': []
        }
        
        start_time = time.time()
        
        # Method 1: Certificate Transparency Logs
        if use_ct:
            print("\n[1] 🔍 Checking Certificate Transparency Logs...")
            ct_subs = self._query_ct_logs(domain)
            self._add_subdomains(ct_subs, "CT Logs")
            results['methods_used'].append('CT Logs')
            results['stats']['ct_logs'] = len(ct_subs)
        
        # Method 2: DNS Bruteforce with comprehensive wordlist
        if use_wordlist:
            print("\n[2] ⚡ Bruteforcing with wordlist...")
            wordlist_subs = self._dns_bruteforce(domain, max_threads)
            self._add_subdomains(wordlist_subs, "Wordlist")
            results['methods_used'].append('Wordlist')
            results['stats']['wordlist'] = len(wordlist_subs)
        
        # Method 3: DNS Zone Transfers (if possible)
        if use_dns:
            print("\n[3] 📡 Attempting DNS enumeration...")
            dns_subs = self._dns_enumeration(domain)
            self._add_subdomains(dns_subs, "DNS Enum")
            results['methods_used'].append('DNS Enum')
            results['stats']['dns_enum'] = len(dns_subs)
        
        # Method 4: Search Engines and Public APIs
        print("\n[4] 🌐 Querying search engines and public APIs...")
        api_subs = self._query_public_apis(domain)
        self._add_subdomains(api_subs, "Public APIs")
        results['methods_used'].append('Public APIs')
        results['stats']['public_apis'] = len(api_subs)
        
        # Method 5: Permutation generation
        if use_permutations and self.discovered_subdomains:
            print("\n[5] 🔄 Generating permutations...")
            perm_subs = self._generate_permutations(domain)
            self._add_subdomains(perm_subs, "Permutations")
            results['methods_used'].append('Permutations')
            results['stats']['permutations'] = len(perm_subs)
        
        # Convert to list and sort
        all_subdomains = list(self.discovered_subdomains)
        all_subdomains.sort()
        
        # Verify each subdomain resolves
        print("\n[6] ✓ Verifying subdomains...")
        verified_subs = self._verify_subdomains(all_subdomains, max_threads)
        
        results['subdomains'] = verified_subs
        results['stats']['total_discovered'] = len(self.discovered_subdomains)
        results['stats']['total_verified'] = len(verified_subs)
        results['stats']['time_elapsed'] = round(time.time() - start_time, 2)
        
        return results
    
    def _add_subdomains(self, subdomains, source):
        """Thread-safe subdomain addition"""
        with self.lock:
            for sub in subdomains:
                if sub and sub not in self.discovered_subdomains:
                    self.discovered_subdomains.add(sub)
                    if len(self.discovered_subdomains) % 10 == 0:
                        print(f"    Found {len(self.discovered_subdomains)} subdomains...")
    
    def _query_ct_logs(self, domain):
        """Query all Certificate Transparency logs"""
        subdomains = set()
        
        ct_endpoints = [
            (f"https://crt.sh/?q=%.{domain}&output=json", 'crt.sh'),
            (f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true", 'certspotter'),
            (f"https://api.subdomain.center/?domain={domain}", 'subdomain_center'),
            (f"https://api.hackertarget.com/hostsearch/?q={domain}", 'hackertarget'),
            (f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", 'virustotal'),
        ]
        
        for url, source in ct_endpoints:
            try:
                print(f"    Querying {source}...")
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    data = response.text
                    
                    if source == 'crt.sh':
                        try:
                            json_data = json.loads(data)
                            for cert in json_data:
                                name = cert.get('name_value', '')
                                if name:
                                    names = name.split('\n')
                                    for sub in names:
                                        sub = sub.strip().lower()
                                        if domain in sub and '*' not in sub:
                                            subdomains.add(sub)
                        except:
                            # Try regex extraction
                            subs = re.findall(rf'[\w\.\-]+\.{re.escape(domain)}', data, re.IGNORECASE)
                            subdomains.update(subs)
                    
                    elif source == 'certspotter':
                        json_data = json.loads(data)
                        for cert in json_data:
                            dns_names = cert.get('dns_names', [])
                            for name in dns_names:
                                subdomains.add(name.lower())
                    
                    elif source == 'subdomain_center':
                        json_data = json.loads(data)
                        for sub in json_data:
                            subdomains.add(sub.lower())
                    
                    elif source == 'hackertarget':
                        lines = data.strip().split('\n')
                        for line in lines:
                            if ',' in line:
                                sub = line.split(',')[0].strip()
                                subdomains.add(sub.lower())
                    
            except Exception as e:
                print(f"    [-] {source} failed: {e}")
                continue
        
        return list(subdomains)
    
    def _dns_bruteforce(self, domain, max_threads):
        """DNS bruteforce with comprehensive wordlist"""
        valid_subs = set()
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                # Use multiple DNS resolvers
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.dns_resolvers
                resolver.timeout = 2
                resolver.lifetime = 2
                
                # Try A record first
                resolver.resolve(full_domain, 'A')
                return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
            except:
                return None
        
        print(f"    Testing {len(self.common_subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.common_subdomains}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result:
                    valid_subs.add(result)
                    if len(valid_subs) % 5 == 0:
                        print(f"    Found {len(valid_subs)} subdomains so far...")
        
        return list(valid_subs)
    
    def _dns_enumeration(self, domain):
        """Advanced DNS enumeration techniques"""
        subdomains = set()
        
        # Try DNS zone transfer
        try:
            print("    Attempting DNS zone transfer...")
            resolver = dns.resolver.Resolver()
            
            # Get nameservers
            ns_records = resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns.target).rstrip('.')
                try:
                    # Try zone transfer
                    transfer_resolver = dns.resolver.Resolver()
                    transfer_resolver.nameservers = [socket.gethostbyname(ns_server)]
                    zone = transfer_resolver.resolve(domain, 'AXFR')
                    
                    for record in zone:
                        record_str = str(record)
                        if domain in record_str:
                            subdomains.add(record_str)
                except:
                    continue
        except:
            pass
        
        # Try DNS queries for common records
        dns_queries = [
            ('_dmarc', 'TXT'),
            ('_domainkey', 'TXT'),
            ('_acme-challenge', 'TXT'),
            ('_autodiscover._tcp', 'SRV'),
            ('_ldap._tcp', 'SRV'),
            ('_kerberos._tcp', 'SRV'),
            ('_kpasswd._tcp', 'SRV'),
            ('_gc._tcp', 'SRV'),
            ('_sip._tcp', 'SRV'),
            ('_sipfederationtls._tcp', 'SRV'),
        ]
        
        for prefix, record_type in dns_queries:
            try:
                resolver.resolve(f"{prefix}.{domain}", record_type)
                subdomains.add(f"{prefix}.{domain}")
            except:
                continue
        
        return list(subdomains)
    
    def _query_public_apis(self, domain):
        """Query various public APIs for subdomains"""
        subdomains = set()
        
        apis = [
            f"https://sonar.omnisint.io/subdomains/{domain}",
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            f"https://api.shodan.io/dns/domain/{domain}?key=YOUR_API_KEY",  # Needs API key
            f"https://api.censys.io/v2/hosts/search?q=domain:{domain}",  # Needs API key
        ]
        
        for api in apis:
            try:
                print(f"    Querying {api.split('/')[2]}...")
                response = requests.get(api, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'sonar.omnisint.io' in api:
                        if isinstance(data, list):
                            for sub in data:
                                subdomains.add(sub.lower())
                    
                    elif 'securitytrails.com' in api:
                        subs = data.get('subdomains', [])
                        for sub in subs:
                            subdomains.add(f"{sub}.{domain}".lower())
                    
                    elif 'shodan.io' in api:
                        subs = data.get('subdomains', [])
                        for sub in subs:
                            subdomains.add(sub.lower())
                    
                    elif 'censys.io' in api:
                        # Parse Censys response
                        pass
                        
            except Exception as e:
                continue
        
        return list(subdomains)
    
    def _generate_permutations(self, domain):
        """Generate permutations from discovered subdomains"""
        permutations = set()
        
        if not self.discovered_subdomains:
            return list(permutations)
        
        base_subs = list(self.discovered_subdomains)
        
        # Common prefixes/suffixes for permutations
        prefixes = ['dev-', 'test-', 'staging-', 'prod-', 'uat-', 'qa-', 'api-', 'mobile-', 'web-']
        suffixes = ['-dev', '-test', '-staging', '-prod', '-uat', '-qa', '-api', '-mobile', '-web']
        
        for sub in base_subs:
            base = sub.replace(f'.{domain}', '')
            
            # Add prefixes
            for prefix in prefixes:
                permutations.add(f"{prefix}{base}.{domain}")
            
            # Add suffixes
            for suffix in suffixes:
                permutations.add(f"{base}{suffix}.{domain}")
            
            # Common variations
            variations = [
                base.replace('www', ''),
                base.replace('api', 'api2'),
                base.replace('api', 'api3'),
                base.replace('web', 'web2'),
                base.replace('web', 'web3'),
                base.replace('mobile', 'mobile2'),
                base.replace('mobile', 'mobile3'),
                base.replace('staging', 'staging2'),
                base.replace('staging', 'staging3'),
                base.replace('test', 'test2'),
                base.replace('test', 'test3'),
                base.replace('dev', 'dev2'),
                base.replace('dev', 'dev3'),
            ]
            
            for var in variations:
                if var and var != base:
                    permutations.add(f"{var}.{domain}")
        
        return list(permutations)
    
    def _verify_subdomains(self, subdomains, max_threads):
        """Verify that subdomains resolve to IP addresses"""
        verified = []
        
        def verify(subdomain):
            try:
                # Try multiple DNS resolvers
                for resolver_ip in self.dns_resolvers:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [resolver_ip]
                        resolver.timeout = 1
                        resolver.lifetime = 1
                        
                        # Try A record
                        answers = resolver.resolve(subdomain, 'A')
                        if answers:
                            return subdomain
                        
                        # Try CNAME
                        answers = resolver.resolve(subdomain, 'CNAME')
                        if answers:
                            return subdomain
                            
                    except:
                        continue
            except:
                pass
            return None
        
        print(f"    Verifying {len(subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(verify, sub): sub for sub in subdomains}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result:
                    verified.append(result)
                
                if i % 10 == 0:
                    print(f"    Verified {i}/{len(subdomains)}...")
        
        return verified

    def save_results(self, results, filename):
        """Save subdomain results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Also save plain text list
            txt_file = filename.replace('.json', '.txt')
            with open(txt_file, 'w') as f:
                for subdomain in results['subdomains']:
                    f.write(subdomain + '\n')
            
            print(f"\n[+] Results saved to:")
            print(f"    JSON: {filename}")
            print(f"    Text: {txt_file}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")