"use client";

import { ArrowUpRight, Unplug } from "lucide-react";
import { useState } from "react";

import { FormDialog } from "@/components/repositories/form-dialog";
import { BUTTON_SMALL } from "@/components/repositories/styles";
import { Button } from "@/components/ui/button";
import type { ActionResult } from "@/lib/repositories";

export function DisconnectButton({
  account,
  manageUrl,
  action,
}: {
  account: string;
  manageUrl: string;
  action: () => Promise<ActionResult>;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="outline" className={BUTTON_SMALL} onClick={() => setOpen(true)}>
        <Unplug className="size-3.5" />
        Disconnect
      </Button>
      <FormDialog
        open={open}
        onOpenChange={setOpen}
        title="Disconnect GitHub"
        description={`Stop ASPM from using ${account}? Its repositories are no longer scanned, but their findings stay visible. You can connect again at any time.`}
        submitLabel="Disconnect"
        action={action}
        danger
      >
        <p className="font-mono text-xs leading-relaxed">
          This only removes the link inside ASPM. To revoke the app&apos;s access completely,
          uninstall it on{" "}
          <a
            href={manageUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
          >
            GitHub
            <ArrowUpRight className="size-3.5" />
          </a>
          .
        </p>
      </FormDialog>
    </>
  );
}
