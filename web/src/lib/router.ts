export type PageMode = "hub" | "detail" | "action" | "utility";
export type FabAction = "post" | "group" | "proposal" | "none";
export type RightRailContext =
  | "login"
  | "home"
  | "feed"
  | "groups"
  | "group_detail"
  | "proposals"
  | "proposal_detail"
  | "disputes"
  | "dispute_detail"
  | "post_create"
  | "poh"
  | "juror"
  | "account"
  | "session_devices"
  | "settings"
  | "tools"
  | "transactions"
  | "content_detail"
  | "thread";

export type RouteDataContract = {
  primaryObject: string;
  accountSnapshot: boolean;
  nodeSnapshot: boolean;
  pendingWorkSlice: boolean;
  contextPanelData: string;
  staleTolerance: {
    liveCriticalMs: number;
    taskRelevantMs: number;
    ambientMs: number;
  };
  blockingDependencies: string[];
};

export type RouteMeta = {
  section: string;
  label: string;
  description: string;
  title: string;
  public: boolean;
  authRequired: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
  mode: PageMode;
  fab: FabAction;
  rightRail: RightRailContext;
  breadcrumbs?: Array<{ label: string; href: string }>;
  dataContract: RouteDataContract;
};

export type RouteMatch =
  | { path: "/login" }
  | { path: "/home" }
  | { path: "/post" }
  | { path: "/poh" }
  | { path: "/juror" }
  | { path: "/tools" }
  | { path: "/feed" }
  | { path: "/groups" }
  | { path: "/groups/:id"; id: string }
  | { path: "/proposals" }
  | { path: "/disputes" }
  | { path: "/disputes/:id"; id: string }
  | { path: "/proposal/:id"; id: string }
  | { path: "/proposals/:id"; id: string }
  | { path: "/settings" }
  | { path: "/session" }
  | { path: "/transactions" }
  | { path: "/account/:account"; account: string }
  | { path: "/content/:id"; id: string }
  | { path: "/thread/:id"; id: string };

export type NavItem = {
  href: string;
  label: string;
  description: string;
  icon: string;
  public: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
  advancedOnly?: boolean;
};

export type NavSection = {
  key: string;
  label: string;
  description: string;
  items: NavItem[];
};

const DEFAULT_STALE_TOLERANCE = {
  liveCriticalMs: 12_000,
  taskRelevantMs: 20_000,
  ambientMs: 45_000,
};

function contract(overrides: Partial<RouteDataContract>): RouteDataContract {
  return {
    primaryObject: overrides.primaryObject || "page",
    accountSnapshot: overrides.accountSnapshot ?? true,
    nodeSnapshot: overrides.nodeSnapshot ?? true,
    pendingWorkSlice: overrides.pendingWorkSlice ?? true,
    contextPanelData: overrides.contextPanelData || "Route context",
    staleTolerance: overrides.staleTolerance ?? DEFAULT_STALE_TOLERANCE,
    blockingDependencies: overrides.blockingDependencies ?? [],
  };
}

const ROUTE_REGISTRY: Record<RouteMatch["path"], RouteMeta> = {
  "/login": {
    section: "Start",
    label: "Login",
    title: "Login",
    description: "Create or restore a device-local identity and establish the session needed for gated protocol actions.",
    public: true,
    authRequired: false,
    mode: "utility",
    fab: "none",
    rightRail: "login",
    dataContract: contract({
      primaryObject: "Authentication state",
      accountSnapshot: false,
      nodeSnapshot: true,
      pendingWorkSlice: false,
      contextPanelData: "Connection and session readiness",
      blockingDependencies: ["Node reachability"],
    }),
  },
  "/home": {
    section: "Home",
    label: "Home",
    title: "Home",
    description: "Mission control for the current session, on-chain standing, and onboarding progress.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "hub",
    fab: "post",
    rightRail: "home",
    dataContract: contract({
      primaryObject: "Home dashboard",
      contextPanelData: "Account posture and quick starts",
      blockingDependencies: ["Auth hydration", "Local signer", "Browser session"],
    }),
  },
  "/post": {
    section: "Social",
    label: "Create post",
    title: "Create post",
    description: "Prepare a post, attach media, and submit a signed transaction with explicit progress states.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "action",
    fab: "none",
    rightRail: "post_create",
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Post composer",
      contextPanelData: "Composer capability and submission posture",
      blockingDependencies: ["Auth hydration", "Node readiness", "Tier 3 posting eligibility"],
    }),
  },
  "/poh": {
    section: "Identity",
    label: "Proof of Humanity",
    title: "Proof of Humanity",
    description: "Review and complete identity progression steps that unlock broader protocol capability.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "poh",
    dataContract: contract({
      primaryObject: "PoH workflow",
      contextPanelData: "Tier progression and eligibility state",
      blockingDependencies: ["Auth hydration", "Account state"],
    }),
  },
  "/juror": {
    section: "Juror work",
    label: "Juror work",
    title: "Juror work",
    description: "Role-gated operational workspace for juror queues, reviews, and decisions.",
    public: false,
    authRequired: true,
    requiresReady: true,
    minPohTier: 3,
    mode: "utility",
    fab: "none",
    rightRail: "juror",
    dataContract: contract({
      primaryObject: "Juror queue",
      contextPanelData: "Juror eligibility and assigned work",
      blockingDependencies: ["Auth hydration", "Juror eligibility", "Node readiness"],
    }),
  },
  "/tools": {
    section: "System",
    label: "Protocol console",
    title: "Protocol console",
    description: "Inspect backend status, readiness, and protocol diagnostics without confusing them with normal user actions.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "tools",
    dataContract: contract({
      primaryObject: "Diagnostics",
      contextPanelData: "Operator and environment diagnostics",
      blockingDependencies: ["Auth hydration", "Node reachability"],
    }),
  },
  "/feed": {
    section: "Social",
    label: "Feed",
    title: "Feed",
    description: "Browse public content and community activity on the protocol.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "post",
    rightRail: "feed",
    dataContract: contract({
      primaryObject: "Feed list",
      contextPanelData: "Feed scope and recent protocol posture",
      blockingDependencies: [],
    }),
  },
  "/groups": {
    section: "Social",
    label: "Groups",
    title: "Groups",
    description: "Browse communities, membership state, and group-scoped activity.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "group",
    rightRail: "groups",
    dataContract: contract({
      primaryObject: "Group list",
      contextPanelData: "Membership summary and discovery posture",
      blockingDependencies: [],
    }),
  },
  "/groups/:id": {
    section: "Social",
    label: "Group detail",
    title: "Group detail",
    description: "Inspect a specific group, its community state, and its available actions.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "group_detail",
    breadcrumbs: [{ label: "Groups", href: "/groups" }],
    dataContract: contract({
      primaryObject: "Group object",
      contextPanelData: "Membership state, member count, and group policy",
      blockingDependencies: ["Authoritative membership state before join or leave"],
    }),
  },
  "/proposals": {
    section: "Governance",
    label: "Proposals",
    title: "Proposals",
    description: "Review proposals, lifecycle stages, and voting actions.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "proposal",
    rightRail: "proposals",
    dataContract: contract({
      primaryObject: "Proposal list",
      contextPanelData: "Proposal counts and vote eligibility",
      blockingDependencies: [],
    }),
  },
  "/proposal/:id": {
    section: "Governance",
    label: "Proposal detail",
    title: "Proposal detail",
    description: "Inspect a single proposal, its current stage, and its available vote or review actions.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "proposal_detail",
    breadcrumbs: [{ label: "Proposals", href: "/proposals" }],
    dataContract: contract({
      primaryObject: "Proposal object",
      contextPanelData: "Stage, tally summary, and vote lock state",
      blockingDependencies: ["Authoritative vote status before one-shot vote enablement"],
    }),
  },
  "/proposals/:id": {
    section: "Governance",
    label: "Proposal detail",
    title: "Proposal detail",
    description: "Inspect a single proposal, its current stage, and its available vote or review actions.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "proposal_detail",
    breadcrumbs: [{ label: "Proposals", href: "/proposals" }],
    dataContract: contract({
      primaryObject: "Proposal object",
      contextPanelData: "Stage, tally summary, and vote lock state",
      blockingDependencies: ["Authoritative vote status before one-shot vote enablement"],
    }),
  },
  "/disputes": {
    section: "Juror work",
    label: "Disputes",
    title: "Disputes",
    description: "Inspect flagged-content disputes and juror voting state from a dedicated surface.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "none",
    rightRail: "disputes",
    dataContract: contract({
      primaryObject: "Dispute queue",
      contextPanelData: "Assignment state and review posture",
      blockingDependencies: [],
    }),
  },
  "/disputes/:id": {
    section: "Juror work",
    label: "Dispute detail",
    title: "Dispute detail",
    description: "Review one dispute, inspect the flagged content and reason, accept juror work, and cast a single juror vote.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "dispute_detail",
    breadcrumbs: [{ label: "Disputes", href: "/disputes" }],
    dataContract: contract({
      primaryObject: "Dispute object",
      contextPanelData: "Assignment, attendance, and vote lock state",
      blockingDependencies: ["Authoritative juror eligibility before review action"],
    }),
  },
  "/settings": {
    section: "System",
    label: "Settings",
    title: "Settings",
    description: "Control connection target, environment, and local client behavior.",
    public: true,
    authRequired: false,
    mode: "utility",
    fab: "none",
    rightRail: "settings",
    dataContract: contract({
      primaryObject: "Settings",
      contextPanelData: "Client environment and behavior controls",
      pendingWorkSlice: false,
      blockingDependencies: [],
    }),
  },
  "/session": {
    section: "Identity",
    label: "Session & devices",
    title: "Session & devices",
    description: "Inspect local signer state, browser session state, and on-chain device records without conflating them.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "session_devices",
    dataContract: contract({
      primaryObject: "Session and device records",
      contextPanelData: "Current device, active session, and revocation posture",
      blockingDependencies: ["Auth hydration", "Session validity"],
    }),
  },
  "/transactions": {
    section: "System",
    label: "Transactions",
    title: "Transactions",
    description: "Track recent submissions from this device and distinguish current queue state from backend-confirmed state.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "transactions",
    dataContract: contract({
      primaryObject: "Recent transaction activity",
      contextPanelData: "Submission lifecycle and reconciliation posture",
      blockingDependencies: ["Auth hydration"],
    }),
  },
  "/account/:account": {
    section: "Identity",
    label: "Account",
    title: "Account",
    description: "Inspect account standing, profile state, and account-scoped actions.",
    public: true,
    authRequired: false,
    mode: "utility",
    fab: "none",
    rightRail: "account",
    dataContract: contract({
      primaryObject: "Account profile",
      contextPanelData: "Standing, keys, and eligibility posture",
      blockingDependencies: [],
    }),
  },
  "/content/:id": {
    section: "Social",
    label: "Content detail",
    title: "Content detail",
    description: "Inspect a specific content object, its metadata, and related actions.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "content_detail",
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Content object",
      contextPanelData: "Content metadata and moderation posture",
      blockingDependencies: [],
    }),
  },
  "/thread/:id": {
    section: "Social",
    label: "Thread",
    title: "Thread",
    description: "Inspect a thread and its ordered discussion activity.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "thread",
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Thread",
      contextPanelData: "Thread lineage and activity posture",
      blockingDependencies: [],
    }),
  },
};

const NAV_SECTIONS: NavSection[] = [
  {
    key: "home",
    label: "Home",
    description: "Primary landing and personal posture.",
    items: [
      {
        href: "/home",
        label: "Home",
        description: "Mission control for this account.",
        icon: "⌂",
        public: false,
        requiresReady: true,
      },
    ],
  },
  {
    key: "social",
    label: "Social",
    description: "Content, publishing, and communities.",
    items: [
      {
        href: "/feed",
        label: "Feed",
        description: "Browse protocol-native content.",
        icon: "≋",
        public: true,
      },
      {
        href: "/groups",
        label: "Groups",
        description: "Browse communities and membership state.",
        icon: "◌",
        public: true,
      },
      {
        href: "/post",
        label: "Create post",
        description: "Publish a signed post transaction.",
        icon: "+",
        public: false,
        requiresReady: true,
      },
    ],
  },
  {
    key: "governance",
    label: "Governance",
    description: "Governance actions and decisions.",
    items: [
      {
        href: "/proposals",
        label: "Proposals",
        description: "Review proposals and vote state.",
        icon: "▣",
        public: true,
      },
    ],
  },
  {
    key: "juror",
    label: "Juror work",
    description: "Disputes, reviews, and role-gated queues.",
    items: [
      {
        href: "/disputes",
        label: "Disputes",
        description: "Inspect active disputes and review posture.",
        icon: "!",
        public: true,
      },
      {
        href: "/juror",
        label: "Juror dashboard",
        description: "Role-gated operational juror workspace.",
        icon: "⚖",
        public: false,
        requiresReady: true,
        minPohTier: 3,
      },
    ],
  },
  {
    key: "identity",
    label: "Identity",
    description: "Identity, PoH, and device state.",
    items: [
      {
        href: "/poh",
        label: "Proof of Humanity",
        description: "Identity progression and unlocks.",
        icon: "◎",
        public: false,
        requiresReady: true,
      },
      {
        href: "/session",
        label: "Session & devices",
        description: "Inspect signer and device state.",
        icon: "☍",
        public: false,
        requiresReady: true,
      },
    ],
  },
  {
    key: "system",
    label: "System",
    description: "Diagnostics and local environment.",
    items: [
      {
        href: "/transactions",
        label: "Transactions",
        description: "Track recent submissions.",
        icon: "⇄",
        public: false,
        requiresReady: true,
        advancedOnly: true,
      },
      {
        href: "/tools",
        label: "Console",
        description: "Inspect backend status.",
        icon: "⌘",
        public: false,
        requiresReady: true,
        advancedOnly: true,
      },
      {
        href: "/settings",
        label: "Settings",
        description: "Connection target and client behavior.",
        icon: "⚙",
        public: true,
      },
    ],
  },
];

function decodeRoutePart(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function matchRoute(path: string): RouteMatch {
  const r = path.split("?")[0];

  if (r === "/" || r === "/login") return { path: "/login" };
  if (r === "/home") return { path: "/home" };
  if (r === "/post") return { path: "/post" };
  if (r === "/poh") return { path: "/poh" };
  if (r === "/juror") return { path: "/juror" };
  if (r === "/tools") return { path: "/tools" };
  if (r === "/feed") return { path: "/feed" };
  if (r === "/groups") return { path: "/groups" };
  if (r === "/proposals") return { path: "/proposals" };
  if (r === "/disputes") return { path: "/disputes" };
  if (r === "/settings") return { path: "/settings" };
  if (r === "/session") return { path: "/session" };
  if (r === "/transactions") return { path: "/transactions" };

  if (r.startsWith("/disputes/")) {
    const id = decodeRoutePart(r.slice("/disputes/".length));
    if (id) return { path: "/disputes/:id", id };
  }

  if (r.startsWith("/groups/")) {
    const id = decodeRoutePart(r.slice("/groups/".length));
    if (id) return { path: "/groups/:id", id };
  }

  if (r.startsWith("/proposal/")) {
    const id = decodeRoutePart(r.slice("/proposal/".length));
    if (id) return { path: "/proposal/:id", id };
  }

  if (r.startsWith("/proposals/")) {
    const id = decodeRoutePart(r.slice("/proposals/".length));
    if (id) return { path: "/proposals/:id", id };
  }

  if (r.startsWith("/account/")) {
    const account = decodeRoutePart(r.slice("/account/".length));
    if (account) return { path: "/account/:account", account };
  }

  if (r.startsWith("/content/")) {
    const id = decodeRoutePart(r.slice("/content/".length));
    if (id) return { path: "/content/:id", id };
  }

  if (r.startsWith("/thread/")) {
    const id = decodeRoutePart(r.slice("/thread/".length));
    if (id) return { path: "/thread/:id", id };
  }

  return { path: "/login" };
}

export function getRouteMeta(route: RouteMatch): RouteMeta {
  return ROUTE_REGISTRY[route.path];
}

export function getNavSections(args: { ready: boolean; tier: number; showAdvanced: boolean }): NavSection[] {
  const { ready, tier, showAdvanced } = args;
  return NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => {
      if (item.advancedOnly && !showAdvanced) return false;
      if (!ready && !item.public) return false;
      if (item.requiresReady && !ready) return false;
      if (typeof item.minPohTier === "number" && tier < item.minPohTier) return false;
      return true;
    }),
  })).filter((section) => section.items.length > 0);
}

export function currentHashPath(): string {
  if (typeof window === "undefined") return "/login";
  const hash = window.location.hash || "#/login";
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const normalized = raw || "/login";
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

export function isPublicRoute(path: string): boolean {
  return getRouteMeta(matchRoute(path)).public;
}

export function isActiveNavPath(currentPath: string, href: string): boolean {
  if (href === "/home") {
    return currentPath === "/" || currentPath === "/home";
  }
  return currentPath === href || currentPath.startsWith(`${href}/`);
}

export function nav(path: string): void {
  const p = path.startsWith("/") ? path : `/${path}`;
  window.location.hash = `#${p}`;
}

export function getDefaultReadyRoute(): RouteMatch {
  return { path: "/home" };
}

export function getFabHref(route: RouteMatch): string | null {
  const meta = getRouteMeta(route);
  switch (meta.fab) {
    case "post":
      return "/post";
    case "group":
      return null;
    case "proposal":
      return null;
    default:
      return null;
  }
}
