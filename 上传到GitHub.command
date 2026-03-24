#!/bin/bash
cd "$(dirname "$0")"
git add -A
git commit -m "更新"
git push
echo ""
echo "上传完成！"
read -p "按回车关闭..."
