export const scanContract = async (file: File) => {
  const formData = new FormData();
  formData.append("file", file);

  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"\;

  const res = await fetch(`${baseUrl}/scan`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) throw new Error("Scan failed");

  return res.json();
};
