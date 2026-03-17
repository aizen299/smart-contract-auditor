import axios from "axios";

export const scanContract = async (file: File) => {
  const formData = new FormData();
  formData.append("file", file);

  const res = await axios.post("http://127.0.0.1:8000/scan", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  return res.data;
};