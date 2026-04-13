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
  | { path: "/proposal/:id"; id: string }
  | { path: "/settings" }
  | { path: "/session" }
  | { path: "/transactions" }
  | { path: "/account/:account"; account: string }
  | { path: "/content/:id"; id: string }
  | { path: "/thread/:id"; id: string };

export type RouteMeta = {
  section: string;
  label: string;
  description: string;
  public: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
};

export type NavItem = {
  href: string;
  label: string;
  description: string;
  icon: string;
  public: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
};

export type NavSection = {
  key: string;
  label: string;
  description: string;
  items: NavItem[];
};

const NAV_SECTIONS: NavSection[] = [
  {
    key: "start",
    label: "Start",
    description: "Connect, restore, and verify readiness.",
    items: [
      {
        href: "/login",
        label: "Login",
        description: "Create or restore this device session.",
        icon: "◉",
        public: true,
      },
      {
        href: "/home",
        label: "Home",
        description: "Mission control for this account.",
        icon: "⌂",
        public: false,
        requiresReady: true,
      },
      {
        href: "/poh",
        label: "PoH",
        description: "Identity progression and unlocks.",
        icon: "◎",
        public: false,
        requiresReady: true,
      },
    ],
  },
  {
    key: "discover",
    label: "Discover",
    description: "Content, publishing, and community.",
    items: [
      {
        href: "/feed",
        label: "Feed",
        description: "Browse public activity.",
        icon: "≋",
        public: true,
      },
      {
        href: "/post",
        label: "Create",
        description: "Publish a post or media.",
        icon: "+",
        public: false,
        requiresReady: true,
      },
      {
        href: "/groups",
        label: "Groups",
        description: "Browse communities and activity.",
        icon: "◌",
        public: true,
      },
    ],
  },
  {
    key: "governance",
    label: "Governance",
    description: "Proposals, votes, and role-gated work.",
    items: [
      {
        href: "/proposals",
        label: "Proposals",
        description: "Review proposals and vote.",
        icon: "▣",
        public: true,
      },
      {
        href: "/juror",
        label: "Juror work",
        description: "Role-gated review queue.",
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
    description: "Session and account-local controls.",
    items: [
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
    key: "protocol",
    label: "Protocol",
    description: "Diagnostics and local environment.",
    items: [
      {
        href: "/transactions",
        label: "Transactions",
        description: "Track recent submissions.",
        icon: "⇄",
        public: false,
        requiresReady: true,
      },
      {
        href: "/tools",
        label: "Console",
        description: "Inspect backend status.",
        icon: "⌘",
        public: false,
        requiresReady: true,
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
  if (r === "/settings") return { path: "/settings" };
  if (r === "/session") return { path: "/session" };
  if (r === "/transactions") return { path: "/transactions" };

  if (r.startsWith("/groups/")) {
    const id = decodeRoutePart(r.slice("/groups/".length));
    if (id) return { path: "/groups/:id", id };
  }

  if (r.startsWith("/proposal/")) {
    const id = decodeRoutePart(r.slice("/proposal/".length));
    if (id) return { path: "/proposal/:id", id };
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
  switch (route.path) {
    case "/login":
      return {
        section: "Start",
        label: "Login",
        description: "Create or restore a device-local identity and establish the session needed for gated protocol actions.",
        public: true,
      };
    case "/home":
      return {
        section: "Start",
        label: "Home",
        description: "Mission control for the current session, on-chain standing, and onboarding progress.",
        public: false,
        requiresReady: true,
      };
    case "/post":
      return {
        section: "Discover",
        label: "Create",
        description: "Prepare a post, attach media, and submit a signed transaction with explicit progress states.",
        public: false,
        requiresReady: true,
      };
    case "/poh":
      return {
        section: "Start",
        label: "Proof of Humanity",
        description: "Review and complete identity progression steps that unlock broader protocol capability.",
        public: false,
        requiresReady: true,
      };
    case "/juror":
      return {
        section: "Governance & Roles",
        label: "Juror work",
        description: "Role-gated operational workspace for juror queues, reviews, and decisions.",
        public: false,
        requiresReady: true,
        minPohTier: 3,
      };
    case "/tools":
      return {
        section: "Protocol",
        label: "Protocol console",
        description: "Inspect backend status, readiness, and protocol diagnostics without confusing them with normal user actions.",
        public: false,
        requiresReady: true,
      };
    case "/transactions":
      return {
        section: "Protocol",
        label: "Transactions",
        description: "Track recent submissions from this device and distinguish current queue state from backend-confirmed state.",
        public: false,
        requiresReady: true,
      };
    case "/session":
      return {
        section: "Identity & Access",
        label: "Session & devices",
        description: "Inspect local signer state, browser session state, and on-chain device records without conflating them.",
        public: false,
        requiresReady: true,
      };
    case "/feed":
      return {
        section: "Discover",
        label: "Feed",
        description: "Browse public content and community activity on the protocol.",
        public: true,
      };
    case "/groups":
      return {
        section: "Discover",
        label: "Groups",
        description: "Browse communities, membership state, and group-scoped activity.",
        public: true,
      };
    case "/groups/:id":
      return {
        section: "Discover",
        label: "Group detail",
        description: "Inspect a specific group, its community state, and its available actions.",
        public: true,
      };
    case "/proposals":
      return {
        section: "Governance & Roles",
        label: "Governance",
        description: "Review proposals, lifecycle stages, and voting actions.",
        public: true,
      };
    case "/proposal/:id":
      return {
        section: "Governance & Roles",
        label: "Proposal detail",
        description: "Inspect a single proposal, its current stage, and its available vote or review actions.",
        public: true,
      };
    case "/settings":
      return {
        section: "Protocol",
        label: "Settings",
        description: "Control connection target, environment, and local client behavior.",
        public: true,
      };
    case "/account/:account":
      return {
        section: "Identity & Access",
        label: "Account",
        description: "Inspect account standing, profile state, and account-scoped actions.",
        public: true,
      };
    case "/content/:id":
      return {
        section: "Discover",
        label: "Content detail",
        description: "Inspect a specific content object, its metadata, and related actions.",
        public: true,
      };
    case "/thread/:id":
      return {
        section: "Discover",
        label: "Thread",
        description: "Inspect a thread and its ordered discussion activity.",
        public: true,
      };
    default:
      return {
        section: "Start",
        label: "WeAll",
        description: "Protocol interface.",
        public: true,
      };
  }
}

export function getNavSections(args: { ready: boolean; tier: number }): NavSection[] {
  const { ready, tier } = args;
  return NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => {
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
