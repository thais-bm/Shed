import {
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Stack,
  Typography,
} from "@mui/material";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";

export default function SafetyNumberDialog({
  open,
  contact,
  safetyNumber,
  onClose,
}) {
  const blocks = safetyNumber?.split(/\s+/).filter(Boolean) ?? [];
  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ pr: 6 }}>
        Verificação de segurança
        <IconButton
          onClick={onClose}
          sx={{ position: "absolute", right: 12, top: 12 }}
        >
          <CloseRoundedIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <Stack alignItems="center" spacing={2} py={1}>
          <VerifiedUserRoundedIcon color="success" sx={{ fontSize: 48 }} />
          <Typography textAlign="center" color="text.secondary">
            Compare este código com <strong>{contact}</strong> por outro canal.
          </Typography>
          <Stack className="safety-number">
            {blocks.map((block) => (
              <Typography key={block} component="span">
                {block}
              </Typography>
            ))}
          </Stack>
          <Typography
            variant="caption"
            color="text.secondary"
            textAlign="center"
          >
            Se os números forem iguais, sua conversa está protegida contra
            interceptação.
          </Typography>
        </Stack>
      </DialogContent>
    </Dialog>
  );
}
