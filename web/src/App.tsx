import { useRoute } from "./lib/router";
import AppShell from "./components/AppShell";

import Home from "./pages/Home";
import PohPage from "./pages/PohPage";
import Tools from "./pages/Tools";

import Feed from "./pages/Feed";
import Groups from "./pages/Groups";
import Group from "./pages/Group";

import Proposals from "./pages/Proposals";
import Proposal from "./pages/Proposal";

import Account from "./pages/Account";
import Content from "./pages/Content";
import Thread from "./pages/Thread";

export default function App() {
  const r = useRoute();

  let page: JSX.Element;
  switch (r.path) {
    case "/home":
      page = <Home />;
      break;
    case "/poh":
      page = <PohPage />;
      break;
    case "/tools":
      page = <Tools />;
      break;

    case "/feed":
      page = <Feed />;
      break;
    case "/groups":
      page = <Groups />;
      break;
    case "/groups/:id":
      page = <Group id={r.id} />;
      break;

    case "/proposals":
      page = <Proposals />;
      break;
    case "/proposal/:id":
      page = <Proposal id={r.id} />;
      break;

    case "/account/:account":
      page = <Account account={r.account} />;
      break;
    case "/content/:id":
      page = <Content id={r.id} />;
      break;
    case "/thread/:id":
      page = <Thread id={r.id} />;
      break;

    default:
      page = <Home />;
  }

  return <AppShell>{page}</AppShell>;
}
